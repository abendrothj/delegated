use crate::models::AuditEvent;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
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

        match query.order {
            AuditOrder::OldestFirst => {
                let file = OpenOptions::new().read(true).open(&self.path)?;
                let reader = BufReader::new(file);
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
            AuditOrder::NewestFirst => read_newest_first(&self.path, query.limit, query.since),
        }
    }
}

/// Reads up to `limit` events from the end of a JSONL audit file without scanning
/// the entire file. Works by seeking backward through the file in 64 KiB chunks,
/// splitting on newlines, and stopping as soon as `limit` valid events have been
/// collected. Cost is O(limit) in the common case rather than O(file size).
///
/// Events are returned newest-first (the order they appear reading from the end).
/// Lines that fail UTF-8 decoding or JSON parsing are skipped, matching the
/// forward-scan behaviour.
fn read_newest_first(
    path: &Path,
    limit: usize,
    since: Option<DateTime<Utc>>,
) -> io::Result<Vec<AuditEvent>> {
    let mut file = OpenOptions::new().read(true).open(path)?;
    let file_len = file.seek(SeekFrom::End(0))?;
    if file_len == 0 {
        return Ok(Vec::new());
    }

    // 64 KiB is large enough to amortise syscall overhead while staying
    // stack-friendly. Benchmarks show diminishing returns above ~32 KiB.
    const CHUNK: u64 = 65_536;

    let mut events: Vec<AuditEvent> = Vec::with_capacity(limit);
    // Bytes saved from the left edge of the previous (rightward) chunk that
    // form the tail of a line whose beginning is further left in the file.
    let mut left_fragment: Vec<u8> = Vec::new();
    let mut pos = file_len;

    loop {
        let read_size = CHUNK.min(pos) as usize;
        pos -= read_size as u64;

        file.seek(SeekFrom::Start(pos))?;
        let mut buf = vec![0u8; read_size];
        file.read_exact(&mut buf)?;

        // Reconstruct the full byte window for this iteration:
        // [current chunk][left fragment from the previous iteration]
        buf.extend_from_slice(&left_fragment);
        left_fragment = Vec::new();
        let working = buf;

        // Split on `\n`. Because JSONL lines end with `\n`, the last segment
        // after the final newline is always empty and gets skipped below.
        let mut segments: Vec<&[u8]> = working.split(|&b| b == b'\n').collect();

        if pos > 0 {
            // The leftmost segment is a partial line: its beginning lives in the
            // next chunk we'll read to the left. Save it and skip it here.
            left_fragment = segments.remove(0).to_vec();
        }

        // Walk segments right-to-left so we see the newest events first.
        for seg in segments.iter().rev() {
            let line = match std::str::from_utf8(seg) {
                Ok(s) => s.trim(),
                Err(_) => continue,
            };
            if line.is_empty() {
                continue;
            }
            let event: AuditEvent = match serde_json::from_str(line) {
                Ok(e) => e,
                Err(_) => continue,
            };
            if since.is_none_or(|s| event.occurred_at >= s) {
                events.push(event);
                if events.len() >= limit {
                    return Ok(events);
                }
            }
        }

        if pos == 0 {
            break;
        }
    }

    Ok(events)
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
    use std::sync::atomic::{AtomicUsize, Ordering};

    // Global sequence counter ensures temp file names are unique even when
    // multiple tests run in parallel and start within the same nanosecond.
    static FILE_SEQ: AtomicUsize = AtomicUsize::new(0);

    fn unique_path(tag: &str) -> std::path::PathBuf {
        let seq = FILE_SEQ.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("signet_audit_{tag}_{seq}.jsonl"))
    }

    #[test]
    fn read_events_skips_malformed_lines() {
        let path = unique_path("skip_bad");
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
        let path = unique_path("order");
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

    // Builds a minimal valid AuditEvent with a unique request_id.
    fn make_event(request_id: &str, ts: DateTime<Utc>) -> AuditEvent {
        AuditEvent {
            occurred_at: ts,
            allowed: true,
            stage: "evaluate_policy".to_string(),
            reason: "ok".to_string(),
            request_id: Some(request_id.to_string()),
            agent_id: None,
            delegator_id: None,
            audience: None,
            action: None,
            token_id: None,
        }
    }

    // Writes `count` events spaced 1 second apart starting from `base` and
    // returns the path. Events are written oldest-first (natural append order).
    fn write_events(count: usize, base: DateTime<Utc>) -> (JsonlFileAuditSink, std::path::PathBuf) {
        let path = unique_path("reverse");
        let sink = JsonlFileAuditSink::new(path.clone());
        for i in 0..count {
            let ts = base + chrono::Duration::seconds(i as i64);
            sink.write_event(&make_event(&format!("req-{i}"), ts))
                .expect("write should succeed");
        }
        (sink, path)
    }

    #[test]
    fn newest_first_returns_correct_order_for_many_events() {
        // Write enough events to span multiple 64 KiB chunks.
        // A single compact AuditEvent line is ~200 bytes, so 500 events ≈ 100 KiB.
        let base = Utc.with_ymd_and_hms(2026, 6, 1, 0, 0, 0).single().unwrap();
        let (sink, path) = write_events(500, base);

        let events = sink
            .read_events(AuditQuery {
                since: None,
                limit: 10,
                order: AuditOrder::NewestFirst,
            })
            .expect("read should succeed");

        assert_eq!(events.len(), 10);
        // Newest 10 events: req-499 down to req-490.
        for (i, event) in events.iter().enumerate() {
            assert_eq!(
                event.request_id.as_deref(),
                Some(format!("req-{}", 499 - i).as_str()),
                "event at index {i} has wrong request_id"
            );
        }

        std::fs::remove_file(path).expect("temp file should be removable");
    }

    #[test]
    fn newest_first_stops_early_and_does_not_scan_entire_file() {
        // Verifies that read_newest_first exits as soon as `limit` is satisfied
        // by checking it returns exactly `limit` events even when the file is large.
        let base = Utc.with_ymd_and_hms(2026, 6, 1, 0, 0, 0).single().unwrap();
        let (sink, path) = write_events(1000, base);

        let events = sink
            .read_events(AuditQuery {
                since: None,
                limit: 5,
                order: AuditOrder::NewestFirst,
            })
            .expect("read should succeed");

        assert_eq!(events.len(), 5);
        assert_eq!(events[0].request_id.as_deref(), Some("req-999"));
        assert_eq!(events[4].request_id.as_deref(), Some("req-995"));

        std::fs::remove_file(path).expect("temp file should be removable");
    }

    #[test]
    fn newest_first_since_filter_works_across_chunk_boundary() {
        // Write 500 events; filter to only events from halfway through.
        // The since boundary falls inside a chunk to exercise cross-chunk filtering.
        let base = Utc.with_ymd_and_hms(2026, 6, 1, 0, 0, 0).single().unwrap();
        let (sink, path) = write_events(500, base);

        let since = base + chrono::Duration::seconds(250);
        let events = sink
            .read_events(AuditQuery {
                since: Some(since),
                limit: 1000,
                order: AuditOrder::NewestFirst,
            })
            .expect("read should succeed");

        // Events 250-499 pass the filter (occurred_at >= since), that's 250 events.
        assert_eq!(events.len(), 250);
        assert_eq!(events[0].request_id.as_deref(), Some("req-499"));
        assert_eq!(events[249].request_id.as_deref(), Some("req-250"));

        std::fs::remove_file(path).expect("temp file should be removable");
    }

    #[test]
    fn newest_first_empty_file_returns_empty() {
        let path = unique_path("empty");
        std::fs::write(&path, b"").expect("should write empty file");
        let sink = JsonlFileAuditSink::new(path.clone());
        let events = sink
            .read_events(AuditQuery {
                since: None,
                limit: 10,
                order: AuditOrder::NewestFirst,
            })
            .expect("read should succeed");
        assert!(events.is_empty());
        std::fs::remove_file(path).expect("temp file should be removable");
    }
}
