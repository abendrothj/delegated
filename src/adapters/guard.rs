use chrono::{DateTime, Duration, Utc};
use std::collections::{HashMap, VecDeque};
use std::hash::{DefaultHasher, Hash, Hasher};
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
    shard_index: usize,
}

#[derive(Debug, Default)]
struct AdapterGuardState {
    request_timestamps: HashMap<String, VecDeque<DateTime<Utc>>>,
    inflight_by_tuple: HashMap<String, usize>,
}

fn remove_tuple_if_idle(state: &mut AdapterGuardState, key: &str) {
    let has_inflight = state
        .inflight_by_tuple
        .get(key)
        .copied()
        .unwrap_or_default()
        > 0;
    let has_recent_timestamps = state
        .request_timestamps
        .get(key)
        .is_some_and(|timestamps| !timestamps.is_empty());
    if !has_inflight && !has_recent_timestamps {
        state.request_timestamps.remove(key);
        state.inflight_by_tuple.remove(key);
    }
}

fn sweep_expired_timestamps(state: &mut AdapterGuardState, cutoff: DateTime<Utc>) {
    let keys: Vec<String> = state.request_timestamps.keys().cloned().collect();
    for key in keys {
        if let Some(timestamps) = state.request_timestamps.get_mut(&key) {
            while matches!(timestamps.front(), Some(ts) if *ts < cutoff) {
                timestamps.pop_front();
            }
        }
        remove_tuple_if_idle(state, &key);
    }
}

const ADAPTER_GUARD_SHARDS: usize = 64;

fn global_guard_shards() -> &'static Vec<Mutex<AdapterGuardState>> {
    static SHARDS: OnceLock<Vec<Mutex<AdapterGuardState>>> = OnceLock::new();
    SHARDS.get_or_init(|| {
        std::iter::repeat_with(|| Mutex::new(AdapterGuardState::default()))
            .take(ADAPTER_GUARD_SHARDS)
            .collect()
    })
}

fn shard_index_for_key(key: &str) -> usize {
    let mut hasher = DefaultHasher::new();
    key.hash(&mut hasher);
    (hasher.finish() as usize) % ADAPTER_GUARD_SHARDS
}

/// Acquires a rate-limit and concurrency lease for the given `(agent_id, delegator_id)` tuple.
///
/// **Process-local**: guard state is held in process-local sharded mutex maps and
/// resets on every process restart. In a multi-process or multi-instance deployment, each
/// instance enforces limits independently — there is no shared counter. This is intentional
/// for low-overhead enforcement within a single process, but callers that need cluster-wide
/// rate limiting must implement it at an upstream layer (e.g., a shared Redis counter or an
/// API gateway).
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
    let shard_index = shard_index_for_key(&key);
    let mut state = global_guard_shards()[shard_index]
        .lock()
        .map_err(|_| AdapterGuardViolation::new("adapter guard state lock poisoned"))?;

    let cutoff = now - Duration::minutes(1);
    sweep_expired_timestamps(&mut state, cutoff);
    {
        let timestamps = state.request_timestamps.entry(key.clone()).or_default();
        if timestamps.len() >= config.max_requests_per_minute {
            return Err(AdapterGuardViolation::new(
                "rate limit exceeded for agent/delegator tuple",
            ));
        }
    }
    remove_tuple_if_idle(&mut state, &key);

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
    Ok(AdapterGuardLease { key, shard_index })
}

impl Drop for AdapterGuardLease {
    fn drop(&mut self) {
        let mut state = match global_guard_shards()[self.shard_index].lock() {
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
        remove_tuple_if_idle(&mut state, &self.key);
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

    fn reset_guard_state_for_tests() {
        for shard in global_guard_shards() {
            if let Ok(mut state) = shard.lock() {
                state.request_timestamps.clear();
                state.inflight_by_tuple.clear();
            }
        }
    }

    #[test]
    fn blocks_requests_after_rate_limit_threshold() {
        reset_guard_state_for_tests();
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
        reset_guard_state_for_tests();
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

    #[test]
    fn prunes_expired_timestamps_for_active_tuple() {
        reset_guard_state_for_tests();
        let (agent_id, delegator_id) = unique_tuple("cleanup");
        let config = AdapterGuardConfig {
            max_requests_per_minute: 5,
            max_inflight_per_tuple: 2,
        };
        let start = now();
        let lease = enter_adapter_guard(&agent_id, &delegator_id, start, &config)
            .expect("initial lease should succeed");
        drop(lease);

        let after_cutoff = start + Duration::minutes(2);
        let second = enter_adapter_guard(&agent_id, &delegator_id, after_cutoff, &config)
            .expect("second lease should succeed");
        drop(second);

        let shard_index = shard_index_for_key(&format!("{agent_id}\u{1f}{delegator_id}"));
        let state = global_guard_shards()[shard_index]
            .lock()
            .expect("guard state should not be poisoned");
        assert_eq!(
            state
                .request_timestamps
                .get(&format!("{agent_id}\u{1f}{delegator_id}"))
                .map_or(0, |timestamps| timestamps.len()),
            1
        );
    }
}
