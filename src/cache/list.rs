use super::detect::{
    detect_cloudflare_caches, detect_hf_caches, detect_java_caches, detect_js_caches,
    detect_js_pm_caches, detect_npx_caches, detect_python_caches, detect_rust_caches,
    detect_torch_caches, detect_vercel_caches,
};
use super::output::{human_since, human_size, print_cache_summary, print_table};
use super::types::{ListResponse, ListSummary};
use std::path::Path;

pub async fn list_caches(
    lang: &str,
    include_npx: bool,
    include_js_pm: bool,
    include_hf: bool,
    include_torch: bool,
    include_vercel: bool,
    include_cloudflare: bool,
    stale_days: Option<u32>,
) -> ListResponse {
    let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));

    let mut entries = Vec::new();
    let has_specialized_flags = include_npx
        || include_js_pm
        || include_hf
        || include_torch
        || include_vercel
        || include_cloudflare;

    // Specialized integrations
    if include_npx {
        entries.extend(detect_npx_caches(stale_days));
    }
    if include_js_pm {
        entries.extend(detect_js_pm_caches());
    }
    if include_hf {
        entries.extend(detect_hf_caches());
    }
    if include_torch {
        entries.extend(detect_torch_caches());
    }
    if include_vercel {
        entries.extend(detect_vercel_caches());
    }
    if include_cloudflare {
        entries.extend(detect_cloudflare_caches());
    }

    // Language-based detection (always runs unless only specialized flags were given)
    if !has_specialized_flags || lang != "auto" {
        if lang == "auto" || lang == "rust" {
            entries.extend(detect_rust_caches(Path::new(&cwd)));
        }
        if lang == "auto" || lang == "js" {
            entries.extend(detect_js_caches(Path::new(&cwd)));
        }
        if lang == "auto" || lang == "py" {
            entries.extend(detect_python_caches());
        }
        if lang == "auto" || lang == "java" {
            entries.extend(detect_java_caches());
        }
    }

    // summary
    let mut total = 0u64;
    let mut stale = 0usize;
    for e in &entries {
        total = total.saturating_add(e.size_bytes);
        if e.stale {
            stale += 1;
        }
    }
    let count = entries.len();
    let resp = ListResponse {
        entries,
        summary: ListSummary {
            total_size_bytes: total,
            count,
            stale_count: stale,
        },
    };
    resp
}

pub fn print_list_table(resp: &ListResponse) {
    let rows = resp
        .entries
        .iter()
        .map(|e| {
            // For NPX entries, show package name and version instead of path
            let display_name = if e.kind == "npx" {
                let version = e
                    .details
                    .get("version")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                format!("{}:{}", e.name, version)
            } else {
                e.path.clone()
            };

            (
                display_name,
                e.kind.clone(),
                human_size(e.size_bytes),
                human_since(e.last_used_at),
                if e.stale {
                    "Yes".to_string()
                } else {
                    "No".to_string()
                },
            )
        })
        .collect::<Vec<_>>();
    print_table(&rows);
    print_cache_summary(resp);
}
