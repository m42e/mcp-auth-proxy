use anyhow::{Context, Result};
use async_trait::async_trait;
use std::path::PathBuf;
use tracing::debug;

use super::CredentialProvider;

/// KeePass credential provider using the `keepass` crate for direct .kdbx access.
///
/// Reference format: `group/entry/field` or just `entry` (defaults to Password field).
/// - `entry` → root-level entry, Password field
/// - `group/entry` → entry in group, Password field
/// - `group/entry/Username` → specific field
pub struct KeePassProvider {
    database_path: PathBuf,
    password_env: String,
    key_file: Option<PathBuf>,
}

impl KeePassProvider {
    pub fn new(database_path: PathBuf, password_env: String, key_file: Option<PathBuf>) -> Self {
        Self {
            database_path,
            password_env,
            key_file,
        }
    }
}

#[async_trait]
impl CredentialProvider for KeePassProvider {
    async fn resolve(&self, reference: &str) -> Result<String> {
        debug!(reference, db = ?self.database_path, "resolving KeePass credential");

        let master_password = std::env::var(&self.password_env).with_context(|| {
            format!(
                "KeePass master password env var '{}' not set",
                self.password_env
            )
        })?;

        let db_path = self.database_path.clone();
        let key_file = self.key_file.clone();
        let reference = reference.to_string();

        // KeePass DB operations are blocking — run in a spawn_blocking
        tokio::task::spawn_blocking(move || {
            resolve_keepass(&db_path, &master_password, key_file.as_deref(), &reference)
        })
        .await
        .context("KeePass task panicked")?
    }
}

fn resolve_keepass(
    db_path: &std::path::Path,
    master_password: &str,
    key_file: Option<&std::path::Path>,
    reference: &str,
) -> Result<String> {
    use keepass::{Database, DatabaseKey};
    use std::fs::File;

    let mut db_file = File::open(db_path)
        .with_context(|| format!("failed to open KeePass database: {}", db_path.display()))?;

    let mut key = DatabaseKey::new();
    key = key.with_password(master_password);

    if let Some(kf_path) = key_file {
        let mut kf = File::open(kf_path)
            .with_context(|| format!("failed to open KeePass key file: {}", kf_path.display()))?;
        key = key.with_keyfile(&mut kf)
            .context("failed to read KeePass key file")?;
    }

    let db = Database::open(&mut db_file, key).context("failed to unlock KeePass database")?;

    // Parse reference: "group/entry/field" or "entry" or "group/entry"
    let parts: Vec<&str> = reference.split('/').collect();
    let (group_path, entry_name, field_name) = match parts.len() {
        1 => (None, parts[0], "Password"),
        2 => (None, parts[0], parts[1]),
        _ => {
            let field = *parts.last().unwrap();
            let entry = parts[parts.len() - 2];
            let group = parts[..parts.len() - 2].join("/");
            (Some(group), entry, field)
        }
    };

    // Search the database
    let root = &db.root;
    let search_group = if let Some(ref gp) = group_path {
        find_group(root, gp)
            .with_context(|| format!("KeePass group '{}' not found", gp))?
    } else {
        root
    };

    // Find entry by title
    for node in &search_group.children {
        if let keepass::db::Node::Entry(entry) = node {
            if entry.get_title() == Some(entry_name) {
                let value = match field_name {
                    "Password" => entry.get_password(),
                    "UserName" | "Username" => entry.get_username(),
                    "URL" => entry.get_url(),
                    _ => entry.get(field_name),
                };
                if let Some(v) = value {
                    return Ok(v.to_string());
                }
                anyhow::bail!(
                    "KeePass entry '{}' has no field '{}'",
                    entry_name,
                    field_name
                );
            }
        }
    }

    anyhow::bail!("KeePass entry '{}' not found", entry_name)
}

fn find_group<'a>(
    group: &'a keepass::db::Group,
    path: &str,
) -> Option<&'a keepass::db::Group> {
    let parts: Vec<&str> = path.split('/').collect();
    let mut current = group;

    for part in parts {
        let mut found = false;
        for node in &current.children {
            if let keepass::db::Node::Group(g) = node {
                if g.name == part {
                    current = g;
                    found = true;
                    break;
                }
            }
        }
        if !found {
            return None;
        }
    }

    Some(current)
}
