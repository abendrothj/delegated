use crate::models::AuditEvent;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fs::OpenOptions;
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

pub trait AuditSink: Send + Sync {
    fn write_event(&self, event: &AuditEvent) -> io::Result<()>;
}

pub trait AuditReader {
    fn read_events(&self, query: AuditQuery) -> io::Result<Vec<AuditEvent>>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOrder {
    NewestFirst,
    OldestFirst,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditQuery {
    pub since: Option<DateTime<Utc>>,
    pub limit: usize,
    pub order: AuditOrder,
}

impl Default for AuditQuery {
    fn default() -> Self {
        Self {
            since: None,
            limit: 100,
            order: AuditOrder::NewestFirst,
        }
    }
}

#[derive(Debug, Clone)]
pub struct JsonlFileAuditSink {
    path: PathBuf,
}

impl JsonlFileAuditSink {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl AuditSink for JsonlFileAuditSink {
    fn write_event(&self, event: &AuditEvent) -> io::Result<()> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        let line = serde_json::to_string(event).map_err(io::Error::other)?;
        writeln!(file, "{line}")
    }
}

impl AuditReader for JsonlFileAuditSink {
    fn read_events(&self, query: AuditQuery) -> io::Result<Vec<AuditEvent>> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        if query.limit == 0 {
            return Ok(Vec::new());
        }

        let file = OpenOptions::new().read(true).open(&self.path)?;
        let reader = BufReader::new(file);
        match query.order {
            AuditOrder::OldestFirst => {
                let mut events = Vec::new();
                for line in reader.lines() {
                    let line = line?;
                    let event: AuditEvent = match serde_json::from_str(&line) {
                        Ok(event) => event,
                        Err(_) => continue,
                    };
                    if let Some(since) = query.since
                        && event.occurred_at < since
                    {
                        continue;
                    }
                    events.push(event);
                    if events.len() >= query.limit {
                        break;
                    }
                }
                Ok(events)
            }
            AuditOrder::NewestFirst => {
                let mut ring = VecDeque::with_capacity(query.limit);
                for line in reader.lines() {
                    let line = line?;
                    let event: AuditEvent = match serde_json::from_str(&line) {
                        Ok(event) => event,
                        Err(_) => continue,
                    };
                    if let Some(since) = query.since
                        && event.occurred_at < since
                    {
                        continue;
                    }
                    if ring.len() >= query.limit {
                        ring.pop_front();
                    }
                    ring.push_back(event);
                }
                Ok(ring.into_iter().rev().collect())
            }
        }
    }
}

pub fn write_audit_event(sink: &dyn AuditSink, event: &AuditEvent) -> io::Result<()> {
    sink.write_event(event)
}

pub fn read_audit_events(
    reader: &dyn AuditReader,
    query: AuditQuery,
) -> io::Result<Vec<AuditEvent>> {
    reader.read_events(query)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn read_events_skips_malformed_lines() {
        let path = std::env::temp_dir().join(format!(
            "delegated_audit_skip_bad_{}.jsonl",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time should be after epoch")
                .as_nanos()
        ));
        std::fs::write(
            &path,
            [
                "{\"broken\":true}\n",
                "{\"not\":\"an audit event\"}\n",
                &format!(
                    "{}\n",
                    serde_json::to_string(&AuditEvent {
                        occurred_at: Utc
                            .with_ymd_and_hms(2026, 6, 1, 20, 0, 0)
                            .single()
                            .expect("valid timestamp"),
                        allowed: true,
                        stage: "allowed".to_string(),
                        reason: "ok".to_string(),
                        request_id: Some("req-1".to_string()),
                        agent_id: Some("agent:example:scheduler:v1".to_string()),
                        delegator_id: Some("user:alice".to_string()),
                        audience: Some("tool:calendar".to_string()),
                        action: Some("calendar.create_event".to_string()),
                        token_id: None,
                    })
                    .expect("event serialization")
                ),
            ]
            .concat(),
        )
        .expect("audit file should be writable");

        let sink = JsonlFileAuditSink::new(path.clone());
        let events = sink
            .read_events(AuditQuery {
                since: None,
                limit: 10,
                order: AuditOrder::NewestFirst,
            })
            .expect("read should succeed");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].request_id.as_deref(), Some("req-1"));

        std::fs::remove_file(path).expect("temporary audit file should be removable");
    }

    #[test]
    fn read_events_defaults_to_newest_first() {
        let path = std::env::temp_dir().join(format!(
            "delegated_audit_order_{}.jsonl",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time should be after epoch")
                .as_nanos()
        ));
        let sink = JsonlFileAuditSink::new(path.clone());
        sink.write_event(&AuditEvent {
            occurred_at: Utc
                .with_ymd_and_hms(2026, 6, 1, 20, 0, 0)
                .single()
                .expect("valid timestamp"),
            allowed: true,
            stage: "s1".to_string(),
            reason: "r1".to_string(),
            request_id: Some("1".to_string()),
            agent_id: None,
            delegator_id: None,
            audience: None,
            action: None,
            token_id: None,
        })
        .expect("write should succeed");
        sink.write_event(&AuditEvent {
            occurred_at: Utc
                .with_ymd_and_hms(2026, 6, 1, 20, 1, 0)
                .single()
                .expect("valid timestamp"),
            allowed: true,
            stage: "s2".to_string(),
            reason: "r2".to_string(),
            request_id: Some("2".to_string()),
            agent_id: None,
            delegator_id: None,
            audience: None,
            action: None,
            token_id: None,
        })
        .expect("write should succeed");

        let events = sink
            .read_events(AuditQuery {
                since: None,
                limit: 2,
                order: AuditOrder::NewestFirst,
            })
            .expect("read should succeed");
        assert_eq!(events[0].request_id.as_deref(), Some("2"));
        assert_eq!(events[1].request_id.as_deref(), Some("1"));

        let oldest = sink
            .read_events(AuditQuery {
                since: None,
                limit: 2,
                order: AuditOrder::OldestFirst,
            })
            .expect("read should succeed");
        assert_eq!(oldest[0].request_id.as_deref(), Some("1"));
        assert_eq!(oldest[1].request_id.as_deref(), Some("2"));

        std::fs::remove_file(path).expect("temporary audit file should be removable");
    }
}
