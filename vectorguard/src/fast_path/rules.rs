use serde::{Deserialize, Serialize};
use std::fs;

use crate::event::{Action, EventType, NormalizedEvent};

/// 규칙 파일(.toml) 최상위 구조
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct RuleSet {
    #[serde(default)]
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Rule {
    pub name:   String,
    pub action: RuleAction,

    // 조건 — 설정된 조건들이 모두 AND로 매칭되어야 함
    /// 프로세스 바이너리명 glob 패턴 (예: "nginx", "py*")
    #[serde(default)]
    pub match_process: Vec<String>,

    /// FileAccess 이벤트의 경로 접두사 (예: "/etc/shadow")
    #[serde(default)]
    pub match_path_prefix: Vec<String>,

    /// Exec 이벤트의 실행파일 경로 접두사 (예: "/bin/sh")
    #[serde(default)]
    pub match_exec_path: Vec<String>,

    /// Network 이벤트의 목적지 포트
    #[serde(default)]
    pub match_port: Vec<u16>,

    /// UID 일치 (0 = root)
    pub match_uid: Option<u32>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RuleAction {
    Block,
    Alert,
    Log,
    Allow,
}

impl RuleAction {
    pub fn to_action(&self) -> Action {
        match self {
            RuleAction::Block          => Action::Blocked,
            RuleAction::Alert          => Action::Alerted,
            RuleAction::Log            => Action::Allowed,
            RuleAction::Allow          => Action::Allowed,
        }
    }
}

impl RuleSet {
    /// rules_path 디렉터리에서 *.toml 파일을 모두 로드
    /// 파일이 없으면 내장 기본 규칙을 사용
    pub fn load_dir(path: &str) -> Self {
        let mut all_rules: Vec<Rule> = Vec::new();

        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.extension().and_then(|e| e.to_str()) == Some("toml") {
                    if let Ok(content) = fs::read_to_string(&p) {
                        match toml::from_str::<RuleSet>(&content) {
                            Ok(rs) => all_rules.extend(rs.rules),
                            Err(e) => tracing::warn!("규칙 파일 파싱 실패 {:?}: {}", p, e),
                        }
                    }
                }
            }
        }

        if all_rules.is_empty() {
            all_rules = Self::builtin_rules();
        }

        RuleSet { rules: all_rules }
    }

    /// 첫 번째 매칭 규칙의 Action 반환 (없으면 None)
    pub fn evaluate(&self, event: &NormalizedEvent) -> Option<Action> {
        self.rules
            .iter()
            .find(|r| r.matches(event))
            .map(|r| r.action.to_action())
    }

    fn builtin_rules() -> Vec<Rule> {
        vec![
            Rule {
                name:              "block-shadow-access".into(),
                action:            RuleAction::Block,
                match_process:     vec![],
                match_path_prefix: vec![
                    "/etc/shadow".into(),
                    "/etc/sudoers".into(),
                    "/etc/gshadow".into(),
                ],
                match_exec_path:   vec![],
                match_port:        vec![],
                match_uid:         None,
            },
            Rule {
                name:              "alert-shell-exec-by-service".into(),
                action:            RuleAction::Alert,
                match_process:     vec!["nginx".into(), "postgres".into(), "apache2".into()],
                match_path_prefix: vec![],
                match_exec_path:   vec![
                    "/bin/sh".into(),
                    "/bin/bash".into(),
                    "/bin/dash".into(),
                    "/usr/bin/python".into(),
                    "/usr/bin/perl".into(),
                ],
                match_port:        vec![],
                match_uid:         None,
            },
            Rule {
                name:              "alert-outbound-unusual-port".into(),
                action:            RuleAction::Alert,
                match_process:     vec![],
                match_path_prefix: vec![],
                match_exec_path:   vec![],
                match_port:        vec![4444, 1337, 31337, 9001, 8888],
                match_uid:         None,
            },
            Rule {
                name:              "alert-root-exec".into(),
                action:            RuleAction::Alert,
                match_process:     vec![],
                match_path_prefix: vec![],
                match_exec_path:   vec!["/usr/bin/wget".into(), "/usr/bin/curl".into(), "/usr/bin/nc".into()],
                match_port:        vec![],
                match_uid:         Some(0),
            },
        ]
    }
}

impl Rule {
    fn matches(&self, event: &NormalizedEvent) -> bool {
        // 프로세스명 glob 필터
        if !self.match_process.is_empty() {
            let binary = &event.process.binary;
            let hit = self.match_process.iter().any(|pat| {
                glob::Pattern::new(pat)
                    .map(|p| p.matches(binary))
                    .unwrap_or(false)
            });
            if !hit {
                return false;
            }
        }

        // UID 필터
        if let Some(uid) = self.match_uid {
            if event.process.uid != uid {
                return false;
            }
        }

        // 포트 필터 (Network 이벤트만 해당)
        if !self.match_port.is_empty() {
            match &event.event_type {
                EventType::Network { port, .. } => {
                    if !self.match_port.contains(port) {
                        return false;
                    }
                }
                _ => return false,
            }
        }

        // 파일 경로 접두사 필터 (FileAccess 이벤트만 해당)
        if !self.match_path_prefix.is_empty() {
            match &event.event_type {
                EventType::FileAccess { path, .. } => {
                    let hit = self.match_path_prefix.iter().any(|p| path.starts_with(p.as_str()));
                    if !hit {
                        return false;
                    }
                }
                _ => return false,
            }
        }

        // Exec 경로 접두사 필터 (Exec 이벤트만 해당)
        if !self.match_exec_path.is_empty() {
            match &event.event_type {
                EventType::Exec => {
                    let binary = &event.process.binary;
                    let hit = self.match_exec_path.iter().any(|p| binary.starts_with(p.as_str()));
                    if !hit {
                        return false;
                    }
                }
                _ => return false,
            }
        }

        true
    }
}
