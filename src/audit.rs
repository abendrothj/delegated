use crate::models::AuditEvent;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

pub trait AuditSink {
    fn write_event(&self, event: &AuditEvent) -> io::Result<()>;
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

pub fn write_audit_event(sink: &dyn AuditSink, event: &AuditEvent) -> io::Result<()> {
    sink.write_event(event)
}
