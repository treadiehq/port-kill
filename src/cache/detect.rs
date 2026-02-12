use super::types::CacheEntry;
use chrono::{DateTime, Utc};
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};

fn dir_size_and_mtime(path: &Path) -> (u64, Option<DateTime<Utc>>) {
    let mut total: u64 = 0;
    let mut newest: Option<DateTime<Utc>> = None;
    let _ = walkdir::WalkDir::new(path).into_iter().for_each(|e| {
        if let Ok(entry) = e {
            if let Ok(md) = entry.metadata() {
                if md.is_file() {
                    total = total.saturating_add(md.len());
                }
                if let Ok(modified) = md.modified() {
                    let dt: DateTime<Utc> = modified.into();
                    newest = Some(match newest {
                        Some(n) => n.max(dt),
                        None => dt,
                    });
                }
            }
        }
    });
    (total, newest)
}

pub fn detect_rust_caches(root: &Path) -> Vec<CacheEntry> {
    let mut entries = Vec::new();

    // project target/
    let target = root.join("target");
    if target.exists() {
        let (size, mtime) = dir_size_and_mtime(&target);
        entries.push(CacheEntry {
            id: "rust:project-target".to_string(),
            kind: "rust".to_string(),
            name: "Rust target".to_string(),
            path: target.to_string_lossy().to_string(),
            size_bytes: size,
            last_used_at: mtime,
            stale: false,
            details: json!({}),
        });
    }

    // ~/.cargo
    if let Ok(home) = std::env::var("HOME") {
        let cargo = PathBuf::from(home).join(".cargo");
        if cargo.exists() {
            let (size, mtime) = dir_size_and_mtime(&cargo);
            entries.push(CacheEntry {
                id: "rust:user-cargo".to_string(),
                kind: "rust".to_string(),
                name: "Cargo cache".to_string(),
                path: cargo.to_string_lossy().to_string(),
                size_bytes: size,
                last_used_at: mtime,
                stale: false,
                details: json!({}),
            });
        }
    }

    entries
}

pub fn detect_js_caches(root: &Path) -> Vec<CacheEntry> {
    let mut entries = Vec::new();

    // Common JS/TS build/cache directories
    let js_dirs = [
        ("node_modules", "js", "Node modules"),
        (".next", "js", "Next.js build"),
        (".vite", "js", "Vite cache"),
        (".nuxt", "js", "Nuxt.js build"),
        (".svelte-kit", "js", "SvelteKit build"),
        (".turbo", "js", "Turborepo cache"),
        ("dist", "js", "Build output"),
        ("build", "js", "Build output"),
        (".cache", "js", "Build cache"),
    ];

    for (dir_name, kind, name) in &js_dirs {
        let dir_path = root.join(dir_name);
        if dir_path.exists() {
            let (size, mtime) = dir_size_and_mtime(&dir_path);
            entries.push(CacheEntry {
                id: format!("js:{}", dir_name),
                kind: kind.to_string(),
                name: name.to_string(),
                path: dir_path.to_string_lossy().to_string(),
                size_bytes: size,
                last_used_at: mtime,
                stale: false, // TODO: implement stale detection
                details: json!({
                    "framework": dir_name,
                    "type": "build_cache"
                }),
            });
        }
    }

    entries
}

pub fn detect_npx_caches(stale_days: Option<u32>) -> Vec<CacheEntry> {
    let mut entries = Vec::new();

    // NPX cache location
    if let Ok(home) = std::env::var("HOME") {
        let npx_cache = PathBuf::from(home).join(".npm/_npx");
        if npx_cache.exists() {
            // Analyze individual packages in NPX cache
            if let Ok(entries_dir) = fs::read_dir(&npx_cache) {
                for entry in entries_dir.flatten() {
                    if entry.path().is_dir() {
                        let package_name = entry.file_name().to_string_lossy().to_string();
                        let package_path = entry.path();
                        let (size, mtime) = dir_size_and_mtime(&package_path);

                        // Determine if package is stale based on stale_days parameter
                        let stale = if let Some(last_used) = mtime {
                            let now = chrono::Utc::now();
                            let days_old = (now - last_used).num_days();
                            let threshold = stale_days.unwrap_or(30); // Default to 30 days
                            days_old > threshold as i64
                        } else {
                            true
                        };

                        // Try to extract package name and version from package.json
                        let (actual_name, version) = extract_package_info(&package_path);

                        entries.push(CacheEntry {
                            id: format!("npx:{}", package_name),
                            kind: "npx".to_string(),
                            name: actual_name.clone(),
                            path: package_path.to_string_lossy().to_string(),
                            size_bytes: size,
                            last_used_at: mtime,
                            stale,
                            details: json!({
                                "type": "npx_package",
                                "version": version,
                                "package_name": actual_name,
                                "hash_name": package_name
                            }),
                        });
                    }
                }
            }
        }
    }

    entries
}

fn extract_package_info(package_path: &Path) -> (String, Option<String>) {
    // First try to get the main package name from the root package.json dependencies
    let root_package_json = package_path.join("package.json");
    if root_package_json.exists() {
        if let Ok(content) = fs::read_to_string(&root_package_json) {
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&content) {
                if let Some(deps) = parsed.get("dependencies").and_then(|d| d.as_object()) {
                    // Get the first dependency name (usually the main package)
                    if let Some((package_name, _)) = deps.iter().next() {
                        // Now look for the actual package in node_modules to get the version
                        let node_modules = package_path.join("node_modules");
                        if node_modules.exists() {
                            let package_dir = node_modules.join(package_name);
                            let package_json = package_dir.join("package.json");
                            if package_json.exists() {
                                if let Ok(content) = fs::read_to_string(&package_json) {
                                    if let Ok(parsed) =
                                        serde_json::from_str::<serde_json::Value>(&content)
                                    {
                                        let version = parsed
                                            .get("version")
                                            .and_then(|v| v.as_str())
                                            .map(|v| v.to_string());
                                        return (package_name.clone(), version);
                                    }
                                }
                            }
                        }
                        return (package_name.clone(), None);
                    }
                }
            }
        }
    }

    // Fallback: look for package.json in node_modules subdirectories
    let node_modules = package_path.join("node_modules");
    if node_modules.exists() {
        if let Ok(entries) = fs::read_dir(&node_modules) {
            for entry in entries.flatten() {
                if entry.path().is_dir() {
                    let package_json = entry.path().join("package.json");
                    if package_json.exists() {
                        if let Ok(content) = fs::read_to_string(&package_json) {
                            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&content)
                            {
                                let name = parsed
                                    .get("name")
                                    .and_then(|n| n.as_str())
                                    .unwrap_or("unknown")
                                    .to_string();
                                let version = parsed
                                    .get("version")
                                    .and_then(|v| v.as_str())
                                    .map(|v| v.to_string());
                                return (name, version);
                            }
                        }
                    }
                }
            }
        }
    }

    ("unknown".to_string(), None)
}

pub fn detect_js_pm_caches() -> Vec<CacheEntry> {
    let mut entries = Vec::new();

    if let Ok(home) = std::env::var("HOME") {
        let home_path = PathBuf::from(home);

        // npm cache
        let npm_cache = home_path.join(".npm");
        if npm_cache.exists() {
            let (size, mtime) = dir_size_and_mtime(&npm_cache);
            entries.push(CacheEntry {
                id: "js-pm:npm".to_string(),
                kind: "js-pm".to_string(),
                name: "npm cache".to_string(),
                path: npm_cache.to_string_lossy().to_string(),
                size_bytes: size,
                last_used_at: mtime,
                stale: false,
                details: json!({"manager": "npm"}),
            });
        }

        // pnpm store
        let pnpm_store = home_path.join(".pnpm-store");
        if pnpm_store.exists() {
            let (size, mtime) = dir_size_and_mtime(&pnpm_store);
            entries.push(CacheEntry {
                id: "js-pm:pnpm".to_string(),
                kind: "js-pm".to_string(),
                name: "pnpm store".to_string(),
                path: pnpm_store.to_string_lossy().to_string(),
                size_bytes: size,
                last_used_at: mtime,
                stale: false,
                details: json!({"manager": "pnpm"}),
            });
        }

        // yarn cache
        let yarn_cache = home_path.join(".yarn/cache");
        if yarn_cache.exists() {
            let (size, mtime) = dir_size_and_mtime(&yarn_cache);
            entries.push(CacheEntry {
                id: "js-pm:yarn".to_string(),
                kind: "js-pm".to_string(),
                name: "yarn cache".to_string(),
                path: yarn_cache.to_string_lossy().to_string(),
                size_bytes: size,
                last_used_at: mtime,
                stale: false,
                details: json!({"manager": "yarn"}),
            });
        }
    }

    entries
}

pub fn detect_python_caches() -> Vec<CacheEntry> {
    let mut entries = Vec::new();
    let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));

    // Scan once and check for all Python cache types, skipping permission errors
    for entry in walkdir::WalkDir::new(&cwd).into_iter().flatten() {
        if !entry.path().is_dir() {
            continue;
        }

        let dir_name = entry.file_name();

        if dir_name == "__pycache__" {
            let (size, mtime) = dir_size_and_mtime(entry.path());
            entries.push(CacheEntry {
                id: format!("python:pycache:{}", entry.path().to_string_lossy()),
                kind: "python".to_string(),
                name: "__pycache__".to_string(),
                path: entry.path().to_string_lossy().to_string(),
                size_bytes: size,
                last_used_at: mtime,
                stale: false,
                details: json!({
                    "type": "pycache"
                }),
            });
        } else if dir_name == ".venv" {
            let (size, mtime) = dir_size_and_mtime(entry.path());
            entries.push(CacheEntry {
                id: format!("python:venv:{}", entry.path().to_string_lossy()),
                kind: "python".to_string(),
                name: "Python virtual environment".to_string(),
                path: entry.path().to_string_lossy().to_string(),
                size_bytes: size,
                last_used_at: mtime,
                stale: false,
                details: json!({
                    "type": "venv"
                }),
            });
        } else if dir_name == ".pytest_cache" {
            let (size, mtime) = dir_size_and_mtime(entry.path());
            entries.push(CacheEntry {
                id: format!("python:pytest:{}", entry.path().to_string_lossy()),
                kind: "python".to_string(),
                name: "pytest cache".to_string(),
                path: entry.path().to_string_lossy().to_string(),
                size_bytes: size,
                last_used_at: mtime,
                stale: false,
                details: json!({
                    "type": "pytest_cache"
                }),
            });
        }
    }

    entries
}

pub fn detect_java_caches() -> Vec<CacheEntry> {
    let mut entries = Vec::new();
    let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));

    // Scan once and check for all Java cache types, skipping permission errors
    for entry in walkdir::WalkDir::new(&cwd).into_iter().flatten() {
        if !entry.path().is_dir() {
            continue;
        }

        let dir_name = entry.file_name();

        if dir_name == ".gradle" {
            let (size, mtime) = dir_size_and_mtime(entry.path());
            entries.push(CacheEntry {
                id: format!("java:gradle:{}", entry.path().to_string_lossy()),
                kind: "java".to_string(),
                name: "Gradle cache".to_string(),
                path: entry.path().to_string_lossy().to_string(),
                size_bytes: size,
                last_used_at: mtime,
                stale: false,
                details: json!({
                    "type": "gradle_cache"
                }),
            });
        } else if dir_name == "build" {
            // Check if this is a Java build directory by looking for Java-specific files
            let has_java_files = walkdir::WalkDir::new(entry.path()).into_iter().any(|e| {
                if let Ok(e) = e {
                    e.path()
                        .extension()
                        .and_then(|ext| ext.to_str())
                        .map(|ext| ext == "class" || ext == "jar")
                        .unwrap_or(false)
                } else {
                    false
                }
            });

            if has_java_files {
                let (size, mtime) = dir_size_and_mtime(entry.path());
                entries.push(CacheEntry {
                    id: format!("java:build:{}", entry.path().to_string_lossy()),
                    kind: "java".to_string(),
                    name: "Java build cache".to_string(),
                    path: entry.path().to_string_lossy().to_string(),
                    size_bytes: size,
                    last_used_at: mtime,
                    stale: false,
                    details: json!({
                        "type": "build_cache"
                    }),
                });
            }
        }
    }

    // Maven cache (~/.m2)
    if let Ok(home) = std::env::var("HOME") {
        let maven_cache = PathBuf::from(home).join(".m2");
        if maven_cache.exists() {
            let (size, mtime) = dir_size_and_mtime(&maven_cache);
            entries.push(CacheEntry {
                id: "maven:cache".to_string(),
                kind: "java".to_string(),
                name: "Maven cache".to_string(),
                path: maven_cache.to_string_lossy().to_string(),
                size_bytes: size,
                last_used_at: mtime,
                stale: false,
                details: json!({
                    "type": "maven_cache"
                }),
            });
        }
    }

    entries
}

pub fn detect_hf_caches() -> Vec<CacheEntry> {
    let mut entries = Vec::new();

    if let Ok(home) = std::env::var("HOME") {
        let home_path = PathBuf::from(home);

        // Hugging Face cache directory
        let hf_cache = home_path.join(".cache/huggingface");
        if hf_cache.exists() {
            let (size, mtime) = dir_size_and_mtime(&hf_cache);
            entries.push(CacheEntry {
                id: "hf:cache".to_string(),
                kind: "hf".to_string(),
                name: "Hugging Face cache".to_string(),
                path: hf_cache.to_string_lossy().to_string(),
                size_bytes: size,
                last_used_at: mtime,
                stale: false,
                details: json!({
                    "type": "hf_cache"
                }),
            });
        }

        // Transformers cache
        let transformers_cache = home_path.join(".cache/torch/transformers");
        if transformers_cache.exists() {
            let (size, mtime) = dir_size_and_mtime(&transformers_cache);
            entries.push(CacheEntry {
                id: "hf:transformers".to_string(),
                kind: "hf".to_string(),
                name: "Transformers cache".to_string(),
                path: transformers_cache.to_string_lossy().to_string(),
                size_bytes: size,
                last_used_at: mtime,
                stale: false,
                details: json!({
                    "type": "transformers_cache"
                }),
            });
        }
    }

    entries
}

pub fn detect_torch_caches() -> Vec<CacheEntry> {
    let mut entries = Vec::new();

    if let Ok(home) = std::env::var("HOME") {
        let home_path = PathBuf::from(home);

        // PyTorch cache directory
        let torch_cache = home_path.join(".cache/torch");
        if torch_cache.exists() {
            let (size, mtime) = dir_size_and_mtime(&torch_cache);
            entries.push(CacheEntry {
                id: "torch:cache".to_string(),
                kind: "torch".to_string(),
                name: "PyTorch cache".to_string(),
                path: torch_cache.to_string_lossy().to_string(),
                size_bytes: size,
                last_used_at: mtime,
                stale: false,
                details: json!({
                    "type": "torch_cache"
                }),
            });
        }

        // PyTorch hub cache
        let hub_cache = home_path.join(".cache/torch/hub");
        if hub_cache.exists() {
            let (size, mtime) = dir_size_and_mtime(&hub_cache);
            entries.push(CacheEntry {
                id: "torch:hub".to_string(),
                kind: "torch".to_string(),
                name: "PyTorch Hub cache".to_string(),
                path: hub_cache.to_string_lossy().to_string(),
                size_bytes: size,
                last_used_at: mtime,
                stale: false,
                details: json!({
                    "type": "torch_hub_cache"
                }),
            });
        }
    }

    entries
}

pub fn detect_vercel_caches() -> Vec<CacheEntry> {
    let mut entries = Vec::new();

    if let Ok(home) = std::env::var("HOME") {
        let home_path = PathBuf::from(home);

        // Vercel cache directory
        let vercel_cache = home_path.join(".vercel");
        if vercel_cache.exists() {
            let (size, mtime) = dir_size_and_mtime(&vercel_cache);
            entries.push(CacheEntry {
                id: "vercel:cache".to_string(),
                kind: "vercel".to_string(),
                name: "Vercel cache".to_string(),
                path: vercel_cache.to_string_lossy().to_string(),
                size_bytes: size,
                last_used_at: mtime,
                stale: false,
                details: json!({
                    "type": "vercel_cache"
                }),
            });
        }
    }

    entries
}

pub fn detect_cloudflare_caches() -> Vec<CacheEntry> {
    let mut entries = Vec::new();

    if let Ok(home) = std::env::var("HOME") {
        let home_path = PathBuf::from(home);

        // Cloudflare cache directory
        let cf_cache = home_path.join(".cloudflare");
        if cf_cache.exists() {
            let (size, mtime) = dir_size_and_mtime(&cf_cache);
            entries.push(CacheEntry {
                id: "cloudflare:cache".to_string(),
                kind: "cloudflare".to_string(),
                name: "Cloudflare cache".to_string(),
                path: cf_cache.to_string_lossy().to_string(),
                size_bytes: size,
                last_used_at: mtime,
                stale: false,
                details: json!({
                    "type": "cloudflare_cache"
                }),
            });
        }
    }

    entries
}
