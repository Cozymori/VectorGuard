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

        let default_action = match cfg.default_action {
            DefaultAction::Block => Action::Blocked,
            DefaultAction::Alert => Action::Alerted,
            DefaultAction::Log   => Action::Allowed,
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

        let action = self.ruleset.evaluate(event).unwrap_or(self.default_action.clone());
        debug!(
            pid = event.process.pid,
            binary = %event.process.binary,
            action = ?action,
            "fast_path evaluation complete"
        );
        event.action = action;
        if matches!(event.action, Action::Blocked | Action::Alerted) {
            event.severity = Severity::High;
        }
    }
}
