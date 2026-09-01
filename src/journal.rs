use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{CliError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalEntry {
    pub session_id: Uuid,
    pub agent_id: Uuid,
    pub app_id: Option<String>,
    pub state: String,
}

#[derive(Default, Serialize, Deserialize)]
struct JournalData {
    sessions: BTreeMap<Uuid, JournalEntry>,
}

pub struct Journal {
    path: PathBuf,
    data: JournalData,
}

impl Journal {
    pub fn open() -> Result<Self> {
        let directories = ProjectDirs::from("run", "Pentagon", "pentagon-cli")
            .ok_or(CliError::CredentialStore)?;
        let state = directories
            .state_dir()
            .unwrap_or_else(|| directories.data_local_dir());
        Self::at(state.join("slack-sessions.json"))
    }

    pub fn at(path: PathBuf) -> Result<Self> {
        let data = match fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|_| CliError::Remote("local_session_journal_invalid".to_owned()))?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => JournalData::default(),
            Err(_) => {
                return Err(CliError::Remote(
                    "local_session_journal_unavailable".to_owned(),
                ));
            }
        };
        Ok(Self { path, data })
    }

    pub fn get(&self, agent_id: Uuid) -> Option<&JournalEntry> {
        self.data.sessions.get(&agent_id)
    }

    pub fn record(&mut self, entry: JournalEntry) -> Result<()> {
        self.data.sessions.insert(entry.agent_id, entry);
        self.save()
    }

    fn save(&self) -> Result<()> {
        let parent = self
            .path
            .parent()
            .ok_or_else(|| CliError::Remote("local_session_journal_invalid".to_owned()))?;
        fs::create_dir_all(parent)
            .map_err(|_| CliError::Remote("local_session_journal_unavailable".to_owned()))?;
        let temporary = self.path.with_extension(format!("tmp-{}", Uuid::new_v4()));
        let bytes = serde_json::to_vec_pretty(&self.data)
            .map_err(|_| CliError::Remote("local_session_journal_invalid".to_owned()))?;
        fs::write(&temporary, bytes)
            .map_err(|_| CliError::Remote("local_session_journal_unavailable".to_owned()))?;
        secure_permissions(&temporary)?;
        fs::rename(&temporary, &self.path)
            .map_err(|_| CliError::Remote("local_session_journal_unavailable".to_owned()))?;
        Ok(())
    }
}

#[cfg(unix)]
fn secure_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|_| CliError::Remote("local_session_journal_unavailable".to_owned()))
}

#[cfg(not(unix))]
fn secure_permissions(_: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Journal, JournalEntry};
    use uuid::Uuid;

    #[test]
    fn journal_persists_only_secret_free_coordinates() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("journal.json");
        let agent = Uuid::new_v4();
        let session = Uuid::new_v4();
        let mut journal = Journal::at(path.clone()).unwrap();
        journal
            .record(JournalEntry {
                session_id: session,
                agent_id: agent,
                app_id: Some("A123".to_owned()),
                state: "oauth_pending".to_owned(),
            })
            .unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(raw.contains("A123"));
        assert!(!raw.contains("token"));
        assert!(!raw.contains("secret"));
        let loaded = Journal::at(path).unwrap();
        assert_eq!(loaded.get(agent).unwrap().session_id, session);
    }
}
