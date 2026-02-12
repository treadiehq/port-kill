use chrono::{DateTime, Utc};
use serde::Serialize;

pub fn print_or_json<T: Serialize + std::fmt::Debug>(value: &T, json: bool) {
    if json {
        match serde_json::to_string_pretty(value) {
            Ok(s) => println!("{}", s),
            Err(e) => eprintln!("Failed to serialize JSON: {}", e),
        }
    } else {
        println!("{:?}", value);
    }
}

pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KB", "MB", "GB", "TB", "PB"];
    if bytes == 0 {
        return "0 B".to_string();
    }

    let mut size = bytes as f64;
    let mut unit_index = 0;

    while size >= 1024.0 && unit_index < UNITS.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }

    format!("{:.2} {}", size, UNITS[unit_index])
}

pub fn human_since(ts: Option<DateTime<Utc>>) -> String {
    match ts {
        None => "-".to_string(),
        Some(t) => {
            let now = Utc::now();
            let dur = now.signed_duration_since(t);
            if dur.num_days() >= 1 {
                format!("{}d ago", dur.num_days())
            } else if dur.num_hours() >= 1 {
                format!("{}h ago", dur.num_hours())
            } else if dur.num_minutes() >= 1 {
                format!("{}m ago", dur.num_minutes())
            } else {
                "just now".to_string()
            }
        }
    }
}

pub fn print_table(rows: &[(String, String, String, String, String)]) {
    // Columns: PACKAGE | KIND | SIZE | LAST USED | STALE?
    // Fixed column widths for proper alignment
    let package_width = 50;
    let kind_width = 8;
    let size_width = 12;
    let last_used_width = 16;
    let stale_width = 6;

    // Header
    println!("{:<package_width$} | {:<kind_width$} | {:<size_width$} | {:<last_used_width$} | {:<stale_width$}", 
              "PACKAGE", "KIND", "SIZE", "LAST USED", "STALE?");
    println!(
        "{}",
        "-".repeat(package_width + kind_width + size_width + last_used_width + stale_width + 16)
    );

    // Data rows
    for (package, kind, size, last, stale) in rows {
        // Truncate package name if too long (character-aware to avoid panic on Unicode)
        let display_package = if package.chars().count() > package_width {
            let truncated: String = package.chars().take(package_width - 3).collect();
            format!("{}...", truncated)
        } else {
            package.clone()
        };

        println!("{:<package_width$} | {:<kind_width$} | {:<size_width$} | {:<last_used_width$} | {:<stale_width$}", 
                  display_package, kind, size, last, stale);
    }
}

pub fn print_cache_summary(resp: &super::types::ListResponse) {
    use std::collections::HashMap;

    println!();
    println!("📊 Cache Summary");
    println!("Total size: {}", human_size(resp.summary.total_size_bytes));
    println!("Total entries: {}", resp.summary.count);
    println!("Stale entries: {}", resp.summary.stale_count);

    // Size by kind breakdown
    let mut kind_sizes: HashMap<String, u64> = HashMap::new();
    for entry in &resp.entries {
        *kind_sizes.entry(entry.kind.clone()).or_insert(0) += entry.size_bytes;
    }

    if !kind_sizes.is_empty() {
        println!();
        println!("Size by kind:");
        let mut sorted_kinds: Vec<_> = kind_sizes.iter().collect();
        sorted_kinds.sort_by(|a, b| b.1.cmp(a.1)); // Sort by size descending

        for (kind, size) in sorted_kinds {
            println!("  {}: {}", kind, human_size(*size));
        }
    }
}
