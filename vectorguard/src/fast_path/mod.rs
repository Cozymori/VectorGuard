mod rules;

use rules::RuleSet;
use tracing::debug;

use crate::config::{DefaultAction, FastPathConfig};
use crate::event::{Action, NormalizedEvent};

pub struct FastPath {
    ruleset:        RuleSet,
    default_action: Action,
    enabled:        bool,
}

impl FastPath {
    pub fn new(cfg: &FastPathConfig) -> Self {
        let ruleset = RuleSet::load_dir(&cfg.rules_path);
        tracing::info!("Fast Path 규칙 로드: {}개", ruleset.rules.len());

        let default_action = match cfg.default_action {
            DefaultAction::Block => Action::Blocked,
            DefaultAction::Alert => Action::Alerted,
            DefaultAction::Log   => Action::Allowed,
        };

        Self { ruleset, default_action, enabled: cfg.enabled }
    }

    /// 이벤트에 Fast Path 규칙을 적용하고 action 필드를 갱신
    pub fn evaluate(&self, event: &mut NormalizedEvent) {
        if !self.enabled {
            return;
        }

        let action = self.ruleset.evaluate(event).unwrap_or(self.default_action.clone());
        debug!(
            pid = event.process.pid,
            binary = %event.process.binary,
            action = ?action,
            "fast_path 평가 완료"
        );
        event.action = action;
    }
}
