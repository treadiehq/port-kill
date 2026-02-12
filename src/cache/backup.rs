use super::types::CacheEntry;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize, Deserialize)]
pub struct BackupManifest {
    pub timestamp: DateTime<Utc>,
    pub entries: Vec<CacheEntry>,
    pub backup_dir: String,
}

pub fn get_backup_dir() -> PathBuf {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(home).join(".cachekill-backup")
}

pub fn create_backup_dir() -> Result<PathBuf, std::io::Error> {
    let backup_dir = get_backup_dir();
    fs::create_dir_all(&backup_dir)?;
    Ok(backup_dir)
}

pub fn get_timestamped_dir() -> PathBuf {
    let backup_dir = get_backup_dir();
    let timestamp = Utc::now().format("%Y-%m-%dT%H-%M-%SZ");
    backup_dir.join(timestamp.to_string())
}

pub async fn safe_delete_entries(
    entries: &[CacheEntry],
    safe_delete: bool,
) -> Result<(Vec<CacheEntry>, Option<String>), std::io::Error> {
    let mut deleted = Vec::new();
    let mut backup_path = None;

    if safe_delete {
        let timestamped_dir = get_timestamped_dir();
        fs::create_dir_all(&timestamped_dir)?;
        backup_path = Some(timestamped_dir.to_string_lossy().to_string());

        // Move entries to backup
        for entry in entries {
            let src = Path::new(&entry.path);
            if src.exists() {
                // Generate unique destination name using entry ID to avoid filename collisions
                // (e.g., multiple __pycache__ directories from different paths)
                let unique_name = format!(
                    "{}-{}",
                    entry.id.replace([':', '/', '\\'], "-"),
                    src.file_name().unwrap_or_default().to_string_lossy()
                );
                let dst = timestamped_dir.join(&unique_name);
                match copy_dir_or_file(src, &dst) {
                    Ok(()) => match remove_dir_or_file(src) {
                        Ok(()) => deleted.push(entry.clone()),
                        Err(e) => {
                            eprintln!(
                                "Warning: Failed to remove original after backup {}: {}",
                                entry.path, e
                            );
                            let _ = remove_dir_or_file(&dst);
                        }
                    },
                    Err(e) => {
                        eprintln!("Warning: Failed to backup {}: {}", entry.path, e);
                    }
                }
            }
        }

        // Create manifest with only successfully backed up entries
        let manifest = BackupManifest {
            timestamp: Utc::now(),
            entries: deleted.clone(),
            backup_dir: timestamped_dir.to_string_lossy().to_string(),
        };

        let manifest_path = timestamped_dir.join("manifest.json");
        let manifest_json = serde_json::to_string_pretty(&manifest)?;
        fs::write(&manifest_path, manifest_json)?;
    } else {
        // Direct deletion without backup
        for entry in entries {
            let path = Path::new(&entry.path);
            if path.exists() {
                if path.is_dir() {
                    if let Err(e) = fs::remove_dir_all(path) {
                        eprintln!("Warning: Failed to delete {}: {}", entry.path, e);
                    } else {
                        deleted.push(entry.clone());
                    }
                } else if path.is_file() {
                    if let Err(e) = fs::remove_file(path) {
                        eprintln!("Warning: Failed to delete {}: {}", entry.path, e);
                    } else {
                        deleted.push(entry.clone());
                    }
                }
            }
        }
    }

    Ok((deleted, backup_path))
}

pub fn find_latest_backup() -> Result<Option<PathBuf>, std::io::Error> {
    let backup_dir = get_backup_dir();
    if !backup_dir.exists() {
        return Ok(None);
    }

    let mut entries: Vec<_> = fs::read_dir(&backup_dir)?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .collect();

    entries.sort_by_key(|e| {
        e.metadata()
            .ok()
            .and_then(|m| m.modified().ok())
            .unwrap_or(std::time::UNIX_EPOCH)
    });

    Ok(entries.last().map(|e| e.path()))
}

pub async fn restore_from_backup(backup_path: &Path) -> Result<usize, std::io::Error> {
    let manifest_path = backup_path.join("manifest.json");
    let manifest_content = fs::read_to_string(&manifest_path)?;
    let manifest: BackupManifest = serde_json::from_str(&manifest_content)?;

    let mut restored_count = 0;

    for entry in &manifest.entries {
        let original_path = Path::new(&entry.path);
        // Use the same unique naming scheme as in safe_delete_entries
        let unique_name = format!(
            "{}-{}",
            entry.id.replace([':', '/', '\\'], "-"),
            original_path.file_name().unwrap_or_default().to_string_lossy()
        );
        let backup_file = backup_path.join(&unique_name);

        if backup_file.exists() {
            // Ensure parent directory exists
            if let Some(parent) = original_path.parent() {
                fs::create_dir_all(parent)?;
            }

            match copy_dir_or_file(&backup_file, original_path) {
                Ok(()) => match remove_dir_or_file(&backup_file) {
                    Ok(()) => restored_count += 1,
                    Err(e) => eprintln!(
                        "Warning: Failed to remove backup after restore {}: {}",
                        entry.path, e
                    ),
                },
                Err(e) => eprintln!("Warning: Failed to restore {}: {}", entry.path, e),
            }
        } else {
            eprintln!("Warning: Backup file not found for {}", entry.path);
        }
    }

    // Clean up backup directory only after ALL files are successfully restored
    // If any files failed to restore, keep the backup so users can retry
    if restored_count > 0 && restored_count == manifest.entries.len() {
        let _ = fs::remove_dir_all(backup_path);
    }

    Ok(restored_count)
}

fn copy_dir_or_file(src: &Path, dst: &Path) -> Result<(), std::io::Error> {
    if src.is_dir() {
        prepare_directory_destination(dst)?;
        copy_dir_recursive(src, dst)
    } else {
        prepare_file_destination(dst)?;
        fs::copy(src, dst)?;
        Ok(())
    }
}

fn prepare_file_destination(dst: &Path) -> Result<(), std::io::Error> {
    if dst.exists() {
        if dst.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "Destination exists and is a directory",
            ));
        }
        fs::remove_file(dst)?;
    }
    Ok(())
}

fn prepare_directory_destination(dst: &Path) -> Result<(), std::io::Error> {
    if dst.exists() {
        if !dst.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "Destination exists and is not a directory",
            ));
        }
        let mut entries = fs::read_dir(dst)?;
        if entries.next().is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "Destination directory is not empty",
            ));
        }
        fs::remove_dir(dst)?;
    }
    Ok(())
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<(), std::io::Error> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let dest_path = dst.join(entry.file_name());

        if file_type.is_symlink() {
            // Preserve symbolic links as links instead of following them
            let target = fs::read_link(entry.path())?;
            #[cfg(unix)]
            {
                std::os::unix::fs::symlink(&target, &dest_path)?;
            }
            #[cfg(windows)]
            {
                // Windows requires knowing if target is a directory or file
                if entry.path().is_dir() {
                    std::os::windows::fs::symlink_dir(&target, &dest_path)?;
                } else {
                    std::os::windows::fs::symlink_file(&target, &dest_path)?;
                }
            }
        } else if file_type.is_dir() {
            copy_dir_recursive(&entry.path(), &dest_path)?;
        } else {
            fs::copy(entry.path(), &dest_path)?;
        }
    }
    Ok(())
}

fn remove_dir_or_file(path: &Path) -> Result<(), std::io::Error> {
    if path.is_dir() {
        fs::remove_dir_all(path)
    } else {
        fs::remove_file(path)
    }
}
