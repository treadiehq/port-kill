use super::backup::{find_latest_backup, restore_from_backup};
use super::types::RestoreResponse;

pub async fn restore_last_backup() -> RestoreResponse {
    match find_latest_backup() {
        Ok(Some(backup_path)) => match restore_from_backup(&backup_path).await {
            Ok(count) => RestoreResponse {
                restored_from: backup_path.to_string_lossy().to_string(),
                restored_count: count,
                error: None,
            },
            Err(e) => {
                eprintln!("Error restoring backup: {}", e);
                RestoreResponse {
                    restored_from: backup_path.to_string_lossy().to_string(),
                    restored_count: 0,
                    error: Some(format!("Failed to restore from backup: {}", e)),
                }
            }
        },
        Ok(None) => {
            eprintln!("No backup found to restore");
            RestoreResponse {
                restored_from: String::new(),
                restored_count: 0,
                error: Some("No backup found to restore".to_string()),
            }
        }
        Err(e) => {
            eprintln!("Error finding backup: {}", e);
            RestoreResponse {
                restored_from: String::new(),
                restored_count: 0,
                error: Some(format!("Failed to find backup: {}", e)),
            }
        }
    }
}
