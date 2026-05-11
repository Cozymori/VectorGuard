pub mod rules;

use rules::RuleSet;
use tracing::debug;

use crate::config::{DefaultAction, FastPathConfig};
use crate::event::{Action, NormalizedEvent, Severity};

pub struct FastPath {
    ruleset:        RuleSet,
    default_action: Action,
    enabled:        bool,
}

impl FastPath {
    pub fn new(cfg: &FastPathConfig) -> Self {
        let ruleset = RuleSet::load_dir(&cfg.rules_path);
        tracing::info!("Fast Path rules loaded: {} rule(s)", ruleset.rules.len());

        // The kernel exposes only 15 chars + NUL in task->comm, so longer
        // process-name patterns can never block in-kernel and will only
        // match in userspace against the truncated comm.
        for r in &ruleset.rules {
            for pat in &r.match_process {
                let literal_len = pat.chars()
                    .take_while(|c| !matches!(c, '*' | '?' | '['))
                    .count();
                if literal_len > 15 {
                    tracing::warn!(
                        "Rule '{}': match_process '{}' exceeds 15 chars; \
                         kernel comm is truncated, so this rule's kernel block \
                         will not fire",
                        r.name, pat
                    );
                }
            }
        }

        let default_action = match cfg.default_action {
            DefaultAction::Block => Action::Blocked,
            DefaultAction::Alert => Action::Alerted,
            DefaultAction::Log   => Action::Logged,
        };

        Self { ruleset, default_action, enabled: cfg.enabled }
    }

    /// Return a reference to all loaded rules (used by the kernel Enforcer)
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn rules(&self) -> &[rules::Rule] {
        &self.ruleset.rules
    }

    /// Apply Fast Path rules to an event and update its action field
    pub fn evaluate(&self, event: &mut NormalizedEvent) {
        if !self.enabled {
            return;
        }

        let (action, rule_name) = self.ruleset.evaluate(event)
            .map(|(a, name)| (a, Some(name)))
            .unwrap_or((self.default_action.clone(), None));
        debug!(
            pid = event.process.pid,
            binary = %event.process.binary,
            action = ?action,
            rule = ?rule_name,
            "fast_path evaluation complete"
        );
        event.action = action;
        event.rule_name = rule_name;
        if matches!(event.action, Action::Blocked | Action::Alerted) {
            event.severity = Severity::High;
        }
    }
}
