use crate::models::AuditEvent;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

pub trait AuditSink {
    fn write_event(&self, event: &AuditEvent) -> io::Result<()>;
}

pub trait AuditReader {
    fn read_events(&self, query: AuditQuery) -> io::Result<Vec<AuditEvent>>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditQuery {
    pub since: Option<DateTime<Utc>>,
    pub limit: usize,
}

impl Default for AuditQuery {
    fn default() -> Self {
        Self {
            since: None,
            limit: 100,
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

        let file = OpenOptions::new().read(true).open(&self.path)?;
        let reader = BufReader::new(file);
        let mut events = Vec::new();
        for line in reader.lines() {
            let line = line?;
            let event: AuditEvent = serde_json::from_str(&line).map_err(io::Error::other)?;
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
