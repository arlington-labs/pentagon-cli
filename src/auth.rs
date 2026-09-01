use std::time::{Duration, Instant};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::Rng;
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};

use crate::{
    CliError, Result,
    api::{DeviceApi, DevicePoll, DeviceProof, DeviceStartRequest, OrganizationEndpoint},
    credential_store::{CredentialLock, CredentialStore},
};

pub trait Browser: Send + Sync {
    fn open(&self, url: &str) -> Result<()>;
}

pub struct SystemBrowser;

impl Browser for SystemBrowser {
    fn open(&self, url: &str) -> Result<()> {
        open::that(url)
            .map(|_| ())
            .map_err(|_| CliError::Remote("browser_open_failed".to_owned()))
    }
}

pub struct LoginReceipt {
    pub device_id: uuid::Uuid,
    pub organization_id: uuid::Uuid,
    pub scopes: Vec<String>,
}

pub async fn access_credential(
    endpoint: &OrganizationEndpoint,
    api: &dyn DeviceApi,
    credentials: &dyn CredentialStore,
) -> Result<SecretString> {
    let _lock = CredentialLock::acquire(&endpoint.keychain_account())?;
    let refresh = credentials
        .get(&endpoint.keychain_account())
        .await?
        .ok_or(CliError::PentagonAuthorizationRequired)?;
    let issued = api.refresh(&refresh).await?;
    credentials
        .set(&endpoint.keychain_account(), &issued.refresh_token)
        .await?;
    Ok(issued.access_token)
}

pub async fn login(
    endpoint: &OrganizationEndpoint,
    api: &dyn DeviceApi,
    credentials: &dyn CredentialStore,
    browser: &dyn Browser,
    device_name: &str,
) -> Result<LoginReceipt> {
    let device_secret = random_secret();
    let pkce_verifier = random_secret();
    let start = api
        .start(&DeviceStartRequest {
            organization_slug: endpoint.slug.clone(),
            device_name: device_name.to_owned(),
            device_secret_hash: hex_sha256(device_secret.expose_secret()),
            pkce_challenge: base64_sha256(pkce_verifier.expose_secret()),
            requested_scopes: vec![
                "agents:read",
                "agents:create",
                "slack-apps:provision",
                "slack-apps:read",
            ],
        })
        .await?;

    println!("Opening {} …", start.verification_uri);
    println!("Enter code: {}", start.human_code);
    println!("Approve this device in your browser.");
    browser.open(start.verification_uri_complete.as_str())?;

    let deadline = Instant::now() + Duration::from_secs(300);
    let interval = Duration::from_secs(start.interval_seconds.clamp(1, 30));
    loop {
        if Instant::now() >= deadline {
            return Err(CliError::DeviceAuthorizationExpired);
        }
        match api
            .poll(&DeviceProof {
                authorization_id: start.authorization_id,
                device_secret: &device_secret,
                pkce_verifier: &pkce_verifier,
            })
            .await?
        {
            DevicePoll::Pending => tokio::time::sleep(interval).await,
            DevicePoll::Denied => return Err(CliError::DeviceAuthorizationDenied),
            DevicePoll::Expired => return Err(CliError::DeviceAuthorizationExpired),
            DevicePoll::Issued(issued) => {
                credentials
                    .set(&endpoint.keychain_account(), &issued.refresh_token)
                    .await?;
                return Ok(LoginReceipt {
                    device_id: issued.device_id,
                    organization_id: issued.organization_id,
                    scopes: issued.scopes,
                });
            }
        }
    }
}

fn random_secret() -> SecretString {
    let mut bytes = [0_u8; 32];
    rand::rng().fill(&mut bytes);
    SecretString::from(URL_SAFE_NO_PAD.encode(bytes))
}

fn hex_sha256(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn base64_sha256(value: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(value.as_bytes()))
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;
    use secrecy::{ExposeSecret, SecretString};
    use url::Url;
    use uuid::Uuid;

    use super::{Browser, login};
    use crate::{
        Result,
        api::{
            DeviceApi, DeviceAuthorization, DeviceCredentials, DevicePoll, DeviceProof,
            DeviceStartRequest, OrganizationEndpoint,
        },
        credential_store::CredentialStore,
    };

    struct FakeApi {
        starts: Mutex<Vec<(String, String, String)>>,
    }

    #[async_trait]
    impl DeviceApi for FakeApi {
        async fn start(&self, request: &DeviceStartRequest) -> Result<DeviceAuthorization> {
            self.starts.lock().unwrap().push((
                request.device_secret_hash.clone(),
                request.pkce_challenge.clone(),
                request.organization_slug.clone(),
            ));
            Ok(DeviceAuthorization {
                contract_version: 1,
                authorization_id: Uuid::nil(),
                human_code: "ABCDE-23456".to_owned(),
                verification_uri: Url::parse("https://example-org.pentagon.run/cli/authorize")
                    .unwrap(),
                verification_uri_complete: Url::parse(
                    "https://example-org.pentagon.run/cli/authorize?code=ABCDE-23456",
                )
                .unwrap(),
                interval_seconds: 1,
                expires_at: "2026-08-30T00:05:00Z".to_owned(),
            })
        }

        async fn poll(&self, proof: &DeviceProof<'_>) -> Result<DevicePoll> {
            assert_eq!(proof.authorization_id, Uuid::nil());
            assert!(proof.device_secret.expose_secret().len() >= 43);
            assert!(proof.pkce_verifier.expose_secret().len() >= 43);
            Ok(DevicePoll::Issued(DeviceCredentials {
                contract_version: 1,
                access_token: SecretString::from(format!("pga_{}", "a".repeat(43))),
                refresh_token: SecretString::from(format!("pgr_{}", "r".repeat(43))),
                access_expires_at: "2026-08-30T00:15:00Z".to_owned(),
                refresh_expires_at: "2026-09-29T00:00:00Z".to_owned(),
                device_id: Uuid::nil(),
                organization_id: Uuid::nil(),
                scopes: vec!["agents:read".to_owned()],
            }))
        }

        async fn refresh(&self, _: &SecretString) -> Result<DeviceCredentials> {
            unreachable!()
        }
    }

    #[derive(Default)]
    struct MemoryStore(Mutex<Option<String>>);

    #[async_trait]
    impl CredentialStore for MemoryStore {
        async fn get(&self, _: &str) -> Result<Option<SecretString>> {
            Ok(self.0.lock().unwrap().clone().map(SecretString::from))
        }
        async fn set(&self, _: &str, credential: &SecretString) -> Result<()> {
            *self.0.lock().unwrap() = Some(credential.expose_secret().to_owned());
            Ok(())
        }
        async fn delete(&self, _: &str) -> Result<()> {
            *self.0.lock().unwrap() = None;
            Ok(())
        }
    }

    #[derive(Default)]
    struct FakeBrowser(Mutex<Vec<String>>);

    impl Browser for FakeBrowser {
        fn open(&self, url: &str) -> Result<()> {
            self.0.lock().unwrap().push(url.to_owned());
            Ok(())
        }
    }

    #[tokio::test]
    async fn login_sends_only_device_proofs_and_stores_only_refresh_credential() {
        let endpoint = OrganizationEndpoint::resolve("example-org").unwrap();
        let api = FakeApi {
            starts: Mutex::new(Vec::new()),
        };
        let store = MemoryStore::default();
        let browser = FakeBrowser::default();
        let receipt = login(&endpoint, &api, &store, &browser, "Test Mac")
            .await
            .unwrap();

        assert_eq!(receipt.scopes, ["agents:read"]);
        let starts = api.starts.lock().unwrap();
        assert_eq!(starts[0].2, "example-org");
        assert_eq!(starts[0].0.len(), 64);
        assert_eq!(starts[0].1.len(), 43);
        assert!(
            store
                .0
                .lock()
                .unwrap()
                .as_deref()
                .unwrap()
                .starts_with("pgr_")
        );
        assert!(browser.0.lock().unwrap()[0].contains("ABCDE-23456"));
    }
}
