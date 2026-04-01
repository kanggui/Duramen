use chrono::{DateTime, Duration, Utc};
use std::io::BufRead;
use std::path::PathBuf;

pub fn run(
    log_path: Option<String>,
    since: Option<String>,
    decision: Option<String>,
    principal: Option<String>,
    limit: usize,
) -> i32 {
    let path = log_path.map(PathBuf::from).unwrap_or_else(|| {
        dirs_next::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".duramen")
            .join("audit.log")
    });

    if !path.exists() {
        println!("[]");
        return 0;
    }

    let file = match std::fs::File::open(&path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!(r#"{{"error":"failed to open audit log: {e}"}}"#);
            return 3;
        }
    };

    let since_threshold = since.as_deref().and_then(parse_since);

    let reader = std::io::BufReader::new(file);
    let mut entries: Vec<serde_json::Value> = Vec::new();

    for line in reader.lines() {
        let line = match line {
            Ok(l) if !l.trim().is_empty() => l,
            _ => continue,
        };

        let value: serde_json::Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => continue,
        };

        // Filter by time
        if let Some(ref threshold) = since_threshold {
            if let Some(ts) = value["timestamp"].as_str() {
                if let Ok(entry_time) = DateTime::parse_from_rfc3339(ts) {
                    if entry_time.with_timezone(&Utc) < *threshold {
                        continue;
                    }
                }
            }
        }

        // Filter by decision
        if let Some(ref filter) = decision {
            if let Some(d) = value["decision"].as_str() {
                if d != filter.as_str() {
                    continue;
                }
            }
        }

        // Filter by principal
        if let Some(ref filter) = principal {
            if let Some(p) = value["principal"]["id"].as_str() {
                if p != filter.as_str() {
                    continue;
                }
            }
        }

        entries.push(value);
    }

    // Take last N entries
    let start = entries.len().saturating_sub(limit);
    let entries = &entries[start..];

    match serde_json::to_string_pretty(entries) {
        Ok(json) => println!("{json}"),
        Err(e) => {
            eprintln!(r#"{{"error":"failed to format entries: {e}"}}"#);
            return 3;
        }
    }

    0
}

fn parse_since(s: &str) -> Option<DateTime<Utc>> {
    let s = s.trim();
    let (num_str, unit) = if let Some(n) = s.strip_suffix('h') {
        (n, "h")
    } else if let Some(n) = s.strip_suffix('d') {
        (n, "d")
    } else if let Some(n) = s.strip_suffix('m') {
        (n, "m")
    } else if let Some(n) = s.strip_suffix('s') {
        (n, "s")
    } else {
        return None;
    };

    let num: i64 = num_str.parse().ok()?;

    #[allow(deprecated)]
    let duration = match unit {
        "h" => Duration::hours(num),
        "d" => Duration::days(num),
        "m" => Duration::minutes(num),
        "s" => Duration::seconds(num),
        _ => return None,
    };

    Some(Utc::now() - duration)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_since_hours() {
        let result = parse_since("1h");
        assert!(result.is_some());
        let threshold = result.unwrap();
        let diff = Utc::now() - threshold;
        assert!(diff.num_minutes() >= 59 && diff.num_minutes() <= 61);
    }

    #[test]
    fn parse_since_days() {
        let result = parse_since("7d");
        assert!(result.is_some());
        let threshold = result.unwrap();
        let diff = Utc::now() - threshold;
        assert!(diff.num_days() >= 6 && diff.num_days() <= 7);
    }

    #[test]
    fn parse_since_invalid() {
        assert!(parse_since("abc").is_none());
        assert!(parse_since("").is_none());
    }
}
