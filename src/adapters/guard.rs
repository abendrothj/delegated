use chrono::{DateTime, Duration, Utc};
use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, OnceLock};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterGuardConfig {
    pub max_requests_per_minute: usize,
    pub max_inflight_per_tuple: usize,
}

impl Default for AdapterGuardConfig {
    fn default() -> Self {
        Self {
            max_requests_per_minute: 120,
            max_inflight_per_tuple: 32,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterGuardViolation {
    pub reason: String,
}

impl AdapterGuardViolation {
    fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

#[derive(Debug)]
pub struct AdapterGuardLease {
    key: String,
}

#[derive(Debug, Default)]
struct AdapterGuardState {
    request_timestamps: HashMap<String, VecDeque<DateTime<Utc>>>,
    inflight_by_tuple: HashMap<String, usize>,
}

fn global_guard_state() -> &'static Mutex<AdapterGuardState> {
    static STATE: OnceLock<Mutex<AdapterGuardState>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(AdapterGuardState::default()))
}

pub fn enter_adapter_guard(
    agent_id: &str,
    delegator_id: &str,
    now: DateTime<Utc>,
    config: &AdapterGuardConfig,
) -> Result<AdapterGuardLease, AdapterGuardViolation> {
    if config.max_requests_per_minute == 0 {
        return Err(AdapterGuardViolation::new(
            "adapter guard misconfigured: max_requests_per_minute must be > 0",
        ));
    }
    if config.max_inflight_per_tuple == 0 {
        return Err(AdapterGuardViolation::new(
            "adapter guard misconfigured: max_inflight_per_tuple must be > 0",
        ));
    }

    let key = format!("{agent_id}\u{1f}{delegator_id}");
    let mut state = global_guard_state()
        .lock()
        .map_err(|_| AdapterGuardViolation::new("adapter guard state lock poisoned"))?;

    let cutoff = now - Duration::minutes(1);
    {
        let timestamps = state.request_timestamps.entry(key.clone()).or_default();
        while matches!(timestamps.front(), Some(ts) if *ts < cutoff) {
            timestamps.pop_front();
        }
        if timestamps.len() >= config.max_requests_per_minute {
            return Err(AdapterGuardViolation::new(
                "rate limit exceeded for agent/delegator tuple",
            ));
        }
    }

    {
        let inflight = state.inflight_by_tuple.entry(key.clone()).or_insert(0);
        if *inflight >= config.max_inflight_per_tuple {
            return Err(AdapterGuardViolation::new(
                "concurrency limit exceeded for agent/delegator tuple",
            ));
        }
        *inflight += 1;
    }

    state
        .request_timestamps
        .entry(key.clone())
        .or_default()
        .push_back(now);
    Ok(AdapterGuardLease { key })
}

impl Drop for AdapterGuardLease {
    fn drop(&mut self) {
        let mut state = match global_guard_state().lock() {
            Ok(guard) => guard,
            Err(_) => return,
        };
        if let Some(inflight) = state.inflight_by_tuple.get_mut(&self.key) {
            if *inflight > 0 {
                *inflight -= 1;
            }
            if *inflight == 0 {
                state.inflight_by_tuple.remove(&self.key);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 6, 1, 20, 20, 0)
            .single()
            .expect("valid timestamp")
    }

    fn unique_tuple(prefix: &str) -> (String, String) {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time should be after epoch")
            .as_nanos();
        (
            format!("agent:{prefix}:{nanos}"),
            format!("user:{prefix}:{nanos}"),
        )
    }

    #[test]
    fn blocks_requests_after_rate_limit_threshold() {
        let (agent_id, delegator_id) = unique_tuple("rate");
        let config = AdapterGuardConfig {
            max_requests_per_minute: 1,
            max_inflight_per_tuple: 8,
        };
        let first = enter_adapter_guard(&agent_id, &delegator_id, now(), &config);
        assert!(first.is_ok());
        drop(first);
        let second = enter_adapter_guard(&agent_id, &delegator_id, now(), &config);
        assert_eq!(
            second.expect_err("second request should be denied").reason,
            "rate limit exceeded for agent/delegator tuple"
        );
    }

    #[test]
    fn blocks_requests_when_concurrency_limit_reached() {
        let (agent_id, delegator_id) = unique_tuple("inflight");
        let config = AdapterGuardConfig {
            max_requests_per_minute: 10,
            max_inflight_per_tuple: 1,
        };
        let first = enter_adapter_guard(&agent_id, &delegator_id, now(), &config)
            .expect("first request should pass guard");
        let second = enter_adapter_guard(&agent_id, &delegator_id, now(), &config);
        assert_eq!(
            second.expect_err("second request should be denied").reason,
            "concurrency limit exceeded for agent/delegator tuple"
        );
        drop(first);
        let third = enter_adapter_guard(&agent_id, &delegator_id, now(), &config);
        assert!(third.is_ok());
    }
}
