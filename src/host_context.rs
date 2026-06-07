use crate::models::HostContext;
use std::collections::HashMap;

/// Builder for [`HostContext`]. All fields default to their zero values via
/// [`HostContext::default()`] — call only the setters you need.
pub struct HostContextBuilder {
    inner: HostContext,
}

impl Default for HostContextBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl HostContextBuilder {
    pub fn new() -> Self {
        Self {
            inner: HostContext::default(),
        }
    }

    pub fn delegation_depth(mut self, depth: u16) -> Self {
        self.inner.delegation_depth = Some(depth);
        self
    }

    pub fn cognitive_judge_scores_bps(mut self, scores: Vec<u16>) -> Self {
        self.inner.cognitive_judge_scores_bps = Some(scores);
        self
    }

    pub fn cognitive_challenge_pass_bps(mut self, pass_bps: u16) -> Self {
        self.inner.cognitive_challenge_pass_bps = Some(pass_bps);
        self
    }

    pub fn reputation_score_bps(mut self, score: u16) -> Self {
        self.inner.reputation_score_bps = Some(score);
        self
    }

    pub fn risk_challenge_passed(mut self, passed: bool) -> Self {
        self.inner.risk_challenge_passed = Some(passed);
        self
    }

    pub fn extra_approval_granted(mut self, granted: bool) -> Self {
        self.inner.extra_approval_granted = Some(granted);
        self
    }

    pub fn clock_leeway_secs(mut self, secs: u64) -> Self {
        self.inner.clock_leeway_secs = secs;
        self
    }

    /// Register a single action alias: `inbound` is what callers send;
    /// `canonical` is what delegation tokens use.
    pub fn action_alias(
        mut self,
        inbound: impl Into<String>,
        canonical: impl Into<String>,
    ) -> Self {
        self.inner
            .action_aliases
            .insert(inbound.into(), canonical.into());
        self
    }

    /// Replace the entire alias map in one call.
    pub fn action_aliases(mut self, aliases: HashMap<String, String>) -> Self {
        self.inner.action_aliases = aliases;
        self
    }

    pub fn build(self) -> HostContext {
        self.inner
    }
}

/// Supplies a [`HostContext`] per request from trusted external sources (reputation
/// services, cognitive oracles, infra-tracked delegation depth, etc.).
///
/// Implement this for dynamic providers. Use [`StaticHostContextProvider`] when a
/// fixed context is sufficient (tests, simple deployments).
pub trait HostContextProvider: Send + Sync {
    fn provide(&self, agent_id: &str, delegator_id: &str) -> HostContext;
}

/// A [`HostContextProvider`] that always returns the same pre-built [`HostContext`].
#[derive(Clone)]
pub struct StaticHostContextProvider {
    context: HostContext,
}

impl StaticHostContextProvider {
    pub fn new(context: HostContext) -> Self {
        Self { context }
    }
}

impl HostContextProvider for StaticHostContextProvider {
    fn provide(&self, _agent_id: &str, _delegator_id: &str) -> HostContext {
        self.context.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_sets_all_fields() {
        let ctx = HostContextBuilder::new()
            .delegation_depth(2)
            .cognitive_judge_scores_bps(vec![9000, 9500])
            .cognitive_challenge_pass_bps(9200)
            .reputation_score_bps(8000)
            .risk_challenge_passed(true)
            .extra_approval_granted(false)
            .clock_leeway_secs(60)
            .build();

        assert_eq!(ctx.delegation_depth, Some(2));
        assert_eq!(ctx.cognitive_judge_scores_bps, Some(vec![9000, 9500]));
        assert_eq!(ctx.cognitive_challenge_pass_bps, Some(9200));
        assert_eq!(ctx.reputation_score_bps, Some(8000));
        assert_eq!(ctx.risk_challenge_passed, Some(true));
        assert_eq!(ctx.extra_approval_granted, Some(false));
        assert_eq!(ctx.clock_leeway_secs, 60);
    }

    #[test]
    fn action_alias_builder_methods() {
        let ctx = HostContextBuilder::new()
            .action_alias("GoogleCalendarCreate", "calendar.create_event")
            .action_alias("calendar_insert", "calendar.create_event")
            .build();

        assert_eq!(
            ctx.action_aliases.get("GoogleCalendarCreate").map(String::as_str),
            Some("calendar.create_event")
        );
        assert_eq!(
            ctx.action_aliases.get("calendar_insert").map(String::as_str),
            Some("calendar.create_event")
        );
        assert!(ctx.action_aliases.get("unknown").is_none());
    }

    #[test]
    fn action_aliases_bulk_replace() {
        let mut map = HashMap::new();
        map.insert("foo".to_string(), "bar".to_string());
        let ctx = HostContextBuilder::new()
            .action_alias("will_be_replaced", "old")
            .action_aliases(map)
            .build();
        assert_eq!(ctx.action_aliases.get("foo").map(String::as_str), Some("bar"));
        assert!(ctx.action_aliases.get("will_be_replaced").is_none());
    }

    #[test]
    fn static_provider_returns_same_context_regardless_of_ids() {
        let ctx = HostContextBuilder::new().delegation_depth(1).build();
        let provider = StaticHostContextProvider::new(ctx);
        let result = provider.provide("agent:foo", "user:bar");
        assert_eq!(result.delegation_depth, Some(1));
        let result2 = provider.provide("agent:other", "user:other");
        assert_eq!(result2.delegation_depth, Some(1));
    }
}
