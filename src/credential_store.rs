use async_trait::async_trait;
use directories::ProjectDirs;
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};
use std::{fs, fs::OpenOptions};

use crate::{CliError, Result};

const SERVICE: &str = "run.pentagon.cli";

#[async_trait]
pub trait CredentialStore: Send + Sync {
    async fn get(&self, account: &str) -> Result<Option<SecretString>>;
    async fn set(&self, account: &str, credential: &SecretString) -> Result<()>;
    async fn delete(&self, account: &str) -> Result<()>;
}

#[derive(Default)]
pub struct OsCredentialStore;

pub struct CredentialLock(fs::File);

impl CredentialLock {
    pub fn acquire(account: &str) -> Result<Self> {
        let directories = ProjectDirs::from("run", "Pentagon", "pentagon-cli")
            .ok_or(CliError::CredentialStore)?;
        let state = directories
            .state_dir()
            .unwrap_or_else(|| directories.data_local_dir());
        let lock_dir = state.join("locks");
        fs::create_dir_all(&lock_dir).map_err(|_| CliError::CredentialStore)?;
        let digest = Sha256::digest(account.as_bytes());
        let name = digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(lock_dir.join(format!("{name}.lock")))
            .map_err(|_| CliError::CredentialStore)?;
        fs2::FileExt::lock_exclusive(&file).map_err(|_| CliError::CredentialStore)?;
        Ok(Self(file))
    }
}

impl Drop for CredentialLock {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.0);
    }
}

#[async_trait]
impl CredentialStore for OsCredentialStore {
    async fn get(&self, account: &str) -> Result<Option<SecretString>> {
        let entry = keyring::Entry::new(SERVICE, account).map_err(|_| CliError::CredentialStore)?;
        match entry.get_password() {
            Ok(value) => Ok(Some(SecretString::from(value))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(_) => Err(CliError::CredentialStore),
        }
    }

    async fn set(&self, account: &str, credential: &SecretString) -> Result<()> {
        keyring::Entry::new(SERVICE, account)
            .and_then(|entry| entry.set_password(credential.expose_secret()))
            .map_err(|_| CliError::CredentialStore)
    }

    async fn delete(&self, account: &str) -> Result<()> {
        let entry = keyring::Entry::new(SERVICE, account).map_err(|_| CliError::CredentialStore)?;
        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(_) => Err(CliError::CredentialStore),
        }
    }
}
