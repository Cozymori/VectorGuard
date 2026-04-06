use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use reqwest::Client;
use serde_json::json;
use tracing::{info, warn};

use crate::config::AiAdvisorConfig;
use crate::event::{Action, EventType, NormalizedEvent};

/// Identifies a repeated security pattern (binary + target + action).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PatternKey {
    binary: String,
    detail: String,
    action: String,
}

pub struct AiAdvisor {
    cfg:            AiAdvisorConfig,
    rules_path:     String,
    window:         VecDeque<(Instant, NormalizedEvent)>,
    counts:         HashMap<PatternKey, u32>,
    cooldowns:      HashMap<PatternKey, Instant>,
    http:           Client,
}

impl AiAdvisor {
    pub fn new(cfg: AiAdvisorConfig, rules_path: String) -> Self {
        Self {
            cfg,
            rules_path,
            window:    VecDeque::new(),
            counts:    HashMap::new(),
            cooldowns: HashMap::new(),
            http:      Client::new(),
        }
    }

    pub fn update_config(&mut self, cfg: AiAdvisorConfig) {
        self.cfg = cfg;
    }

    pub async fn analyze(&mut self, event: &NormalizedEvent) {
        if !self.cfg.enabled || self.cfg.api_key.is_empty() {
            return;
        }

        // Only track blocked or alerted events
        if !matches!(event.action, Action::Blocked | Action::Alerted | Action::Killed) {
            return;
        }

        let key = match Self::pattern_key(event) {
            Some(k) => k,
            None => return,
        };

        let now = Instant::now();
        let window_dur = Duration::from_secs(self.cfg.window_secs);

        // Evict expired events
        while let Some((ts, _)) = self.window.front() {
            if now.duration_since(*ts) > window_dur {
                let (_, old) = self.window.pop_front().unwrap();
                if let Some(old_key) = Self::pattern_key(&old) {
                    if let Some(c) = self.counts.get_mut(&old_key) {
                        *c = c.saturating_sub(1);
                        if *c == 0 { self.counts.remove(&old_key); }
                    }
                }
            } else {
                break;
            }
        }

        self.window.push_back((now, event.clone()));
        let count = self.counts.entry(key.clone()).or_insert(0);
        *count += 1;

        if *count < self.cfg.trigger_threshold {
            return;
        }

        // Check cooldown
        if let Some(&last) = self.cooldowns.get(&key) {
            if now.duration_since(last) < Duration::from_secs(self.cfg.cooldown_seconds) {
                return;
            }
        }
        self.cooldowns.insert(key.clone(), now);

        info!("AI advisor triggered: pattern={:?} count={}", key, count);

        // Collect context events (most recent first)
        let context: Vec<NormalizedEvent> = self.window.iter()
            .rev()
            .take(self.cfg.context_window_size)
            .map(|(_, ev)| ev.clone())
            .collect();

        self.call_claude(context).await;
    }

    fn pattern_key(event: &NormalizedEvent) -> Option<PatternKey> {
        let detail = match &event.event_type {
            EventType::FileAccess { path, .. } => path.clone(),
            EventType::Network { port, .. }    => port.to_string(),
            EventType::Exec                    => event.process.binary.clone(),
            _ => return None,
        };
        Some(PatternKey {
            binary: event.process.binary.clone(),
            detail,
            action: format!("{:?}", event.action),
        })
    }

    async fn call_claude(&self, context: Vec<NormalizedEvent>) {
        let events_summary: Vec<String> = context.iter().map(|ev| {
            let type_str = match &ev.event_type {
                EventType::FileAccess { path, .. }           => format!("file_access path={}", path),
                EventType::Network { port, remote_ip, .. }   => format!("network remote={}:{}", remote_ip, port),
                EventType::Exec                              => "exec".to_string(),
                EventType::Privilege { syscall, .. }         => format!("privilege syscall={}", syscall),
                EventType::Signal { signum, .. }             => format!("signal sig={}", signum),
            };
            format!(
                "binary={} uid={} action={:?} type={} rule={:?}",
                ev.process.binary,
                ev.process.uid,
                ev.action,
                type_str,
                ev.rule_name,
            )
        }).collect();

        let current_rules = self.load_current_rules();

        let prompt = format!(
            "You are a security rule advisor for VectorGuard, an eBPF-based security monitoring tool.\n\
             \n\
             Current fast-path rules (TOML):\n\
             ```toml\n{current_rules}```\n\
             \n\
             Recent anomalous events (repeated pattern detected):\n\
             {events}\n\
             \n\
             Based on this pattern, suggest 1-3 new security rules. \
             Use this TOML structure (all match fields are optional, AND-combined):\n\
             ```toml\n\
             [[rules]]\n\
             name              = \"rule-name\"      # unique, kebab-case\n\
             action            = \"alert\"           # block | alert | log\n\
             match_process     = [\"binary\"]        # process comm name globs\n\
             match_path_prefix = [\"/path/\"]       # file path prefixes\n\
             match_exec_path   = [\"/bin/sh\"]      # executed binary path prefixes\n\
             match_port        = [4444]             # destination ports\n\
             match_uid         = 0                  # user ID\n\
             ```\n\
             Reply with only the TOML block(s), no commentary.",
            current_rules = current_rules,
            events = events_summary.join("\n"),
        );

        let model = if self.cfg.model.is_empty() { "gpt-4o" } else { &self.cfg.model };
        let body = json!({
            "model": model,
            "max_tokens": 1024,
            "messages": [{"role": "user", "content": prompt}]
        });

        let resp = match self.http
            .post("https://api.openai.com/v1/chat/completions")
            .header("Authorization", format!("Bearer {}", self.cfg.api_key))
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
        {
            Ok(r)  => r,
            Err(e) => { warn!("AI advisor HTTP error: {}", e); return; }
        };

        let json_resp: serde_json::Value = match resp.json().await {
            Ok(j)  => j,
            Err(e) => { warn!("AI advisor response parse error: {}", e); return; }
        };

        let text = json_resp["choices"][0]["message"]["content"].as_str().unwrap_or("");
        let toml_block = Self::extract_toml(text);

        if toml_block.is_empty() {
            warn!("AI advisor: no TOML found in Claude response");
            return;
        }

        // Validate before writing
        if let Err(e) = toml::from_str::<toml::Value>(&toml_block) {
            warn!("AI advisor: invalid TOML from Claude: {}", e);
            return;
        }

        let out_path = PathBuf::from(&self.rules_path).join("ai-generated.toml");
        let header = "# Auto-generated by VectorGuard AI Advisor — do not edit manually\n\n";
        match std::fs::write(&out_path, format!("{}{}", header, toml_block)) {
            Ok(_)  => info!("AI advisor: rules written to {}", out_path.display()),
            Err(e) => warn!("AI advisor: failed to write rules: {}", e),
        }
    }

    fn load_current_rules(&self) -> String {
        let mut out = String::new();
        if let Ok(entries) = std::fs::read_dir(&self.rules_path) {
            let mut paths: Vec<_> = entries.flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().map(|e| e == "toml").unwrap_or(false))
                .collect();
            paths.sort();
            for p in paths {
                if let Ok(content) = std::fs::read_to_string(&p) {
                    out.push_str(&content);
                    out.push('\n');
                }
            }
        }
        out
    }

    /// Extract TOML from a fenced code block (```toml ... ```) or raw content.
    fn extract_toml(text: &str) -> String {
        let mut result = String::new();
        let mut in_block = false;

        for line in text.lines() {
            if !in_block {
                if line.starts_with("```toml") || line.trim_start().starts_with("```toml") {
                    in_block = true;
                }
            } else if line.trim() == "```" {
                in_block = false;
            } else {
                result.push_str(line);
                result.push('\n');
            }
        }

        // Fallback: raw TOML with no fence
        if result.is_empty() && text.contains("[[rules]]") {
            return text.to_string();
        }

        result
    }
}
