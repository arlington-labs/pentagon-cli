use std::time::Duration;

use async_trait::async_trait;
use reqwest::StatusCode;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;
use uuid::Uuid;

use crate::{CliError, Result};

pub const CONTRACT_VERSION: u8 = 1;
const PENTAGON_DOMAIN: &str = "pentagon.run";

#[derive(Debug, Clone)]
pub struct OrganizationEndpoint {
    pub slug: String,
    pub base_url: Url,
}

impl OrganizationEndpoint {
    pub fn resolve(slug: &str) -> Result<Self> {
        let slug = slug.trim().to_ascii_lowercase();
        if !valid_organization_slug(&slug) {
            return Err(CliError::InvalidInput("invalid organization slug"));
        }
        let base_url = match std::env::var("PENTAGON_CLI_API_URL") {
            Ok(configured) => {
                let url = Url::parse(&configured)
                    .map_err(|_| CliError::InvalidInput("invalid Pentagon API URL"))?;
                if !allowed_local_api_override(&url) {
                    return Err(CliError::InvalidInput(
                        "Pentagon API override must use a loopback address",
                    ));
                }
                url
            }
            Err(_) => Url::parse(&format!("https://{slug}.{PENTAGON_DOMAIN}/api/cli/"))
                .expect("validated organization slug produces a valid Pentagon URL"),
        };
        Ok(Self { slug, base_url })
    }

    pub fn keychain_account(&self) -> String {
        format!(
            "{}:{}:{}:refresh",
            self.base_url.host_str().unwrap_or("unknown"),
            self.base_url.port_or_known_default().unwrap_or(0),
            self.slug
        )
    }

    pub fn slack_keychain_account(&self) -> String {
        format!(
            "{}:{}:{}:slack-configuration-refresh",
            self.base_url.host_str().unwrap_or("unknown"),
            self.base_url.port_or_known_default().unwrap_or(0),
            self.slug
        )
    }
}

fn valid_organization_slug(value: &str) -> bool {
    (2..=63).contains(&value.len())
        && value.starts_with(|character: char| character.is_ascii_lowercase())
        && value.ends_with(|character: char| {
            character.is_ascii_lowercase() || character.is_ascii_digit()
        })
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn allowed_local_api_override(url: &Url) -> bool {
    matches!(url.scheme(), "http" | "https")
        && matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"))
}

#[derive(Debug)]
pub struct DeviceStartRequest {
    pub organization_slug: String,
    pub device_name: String,
    pub device_secret_hash: String,
    pub pkce_challenge: String,
    pub requested_scopes: Vec<&'static str>,
}

#[derive(Debug, Deserialize)]
pub struct DeviceAuthorization {
    pub contract_version: u8,
    pub authorization_id: Uuid,
    pub human_code: String,
    pub verification_uri: Url,
    pub verification_uri_complete: Url,
    pub interval_seconds: u64,
    pub expires_at: String,
}

#[derive(Debug)]
pub struct DeviceProof<'a> {
    pub authorization_id: Uuid,
    pub device_secret: &'a SecretString,
    pub pkce_verifier: &'a SecretString,
}

#[derive(Debug)]
pub enum DevicePoll {
    Pending,
    Issued(DeviceCredentials),
    Denied,
    Expired,
}

#[derive(Debug, Deserialize)]
pub struct DeviceCredentials {
    pub contract_version: u8,
    pub access_token: SecretString,
    pub refresh_token: SecretString,
    pub access_expires_at: String,
    pub refresh_expires_at: String,
    pub device_id: Uuid,
    pub organization_id: Uuid,
    pub scopes: Vec<String>,
}

#[async_trait]
pub trait DeviceApi: Send + Sync {
    async fn start(&self, request: &DeviceStartRequest) -> Result<DeviceAuthorization>;
    async fn poll(&self, proof: &DeviceProof<'_>) -> Result<DevicePoll>;
    async fn refresh(&self, refresh: &SecretString) -> Result<DeviceCredentials>;
}

#[async_trait]
pub trait DeviceRevocationApi: Send + Sync {
    async fn revoke_device(&self, access: &SecretString, device_id: Uuid) -> Result<()>;
}

pub struct HttpPentagonApi {
    client: reqwest::Client,
    endpoint: OrganizationEndpoint,
}

impl HttpPentagonApi {
    pub fn new(endpoint: OrganizationEndpoint) -> Result<Self> {
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .user_agent(concat!("pentagon-cli/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|_| CliError::Remote("http_client_initialization_failed".to_owned()))?;
        Ok(Self { client, endpoint })
    }

    fn url(&self, path: &str) -> Result<Url> {
        self.endpoint
            .base_url
            .join(path)
            .map_err(|_| CliError::Remote("endpoint_construction_failed".to_owned()))
    }

    async fn safe_error(response: reqwest::Response) -> CliError {
        let status = response.status();
        let code = response
            .json::<StateBody>()
            .await
            .ok()
            .and_then(|body| body.error.or(body.state))
            .filter(|value| {
                value.chars().all(|c| {
                    c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | ':' | '-')
                })
            })
            .unwrap_or_else(|| format!("http_{}", status.as_u16()));
        match code.as_str() {
            "workspace_already_bound" => CliError::WorkspaceAlreadyBound,
            "organization_already_bound_to_workspace" => {
                CliError::OrganizationAlreadyBoundToWorkspace
            }
            _ => CliError::Remote(code),
        }
    }
}

#[derive(Serialize)]
struct StartBody<'a> {
    organization_slug: &'a str,
    device_name: &'a str,
    device_secret_hash: &'a str,
    pkce_challenge: &'a str,
    requested_scopes: &'a [&'static str],
}

#[derive(Serialize)]
struct PollBody<'a> {
    authorization_id: Uuid,
    device_secret: &'a str,
    pkce_verifier: &'a str,
}

#[derive(Serialize)]
struct RefreshBody<'a> {
    refresh_token: &'a str,
}

#[derive(Deserialize)]
struct StateBody {
    state: Option<String>,
    error: Option<String>,
}

#[async_trait]
impl DeviceApi for HttpPentagonApi {
    async fn start(&self, request: &DeviceStartRequest) -> Result<DeviceAuthorization> {
        let response = self
            .client
            .post(self.url("device/start")?)
            .json(&StartBody {
                organization_slug: &request.organization_slug,
                device_name: &request.device_name,
                device_secret_hash: &request.device_secret_hash,
                pkce_challenge: &request.pkce_challenge,
                requested_scopes: &request.requested_scopes,
            })
            .send()
            .await
            .map_err(|_| CliError::Remote("device_start_unavailable".to_owned()))?;
        if !response.status().is_success() {
            return Err(CliError::Remote(format!(
                "device_start_http_{}",
                response.status().as_u16()
            )));
        }
        let authorization: DeviceAuthorization = response
            .json()
            .await
            .map_err(|_| CliError::Remote("device_start_malformed".to_owned()))?;
        if authorization.contract_version != CONTRACT_VERSION {
            return Err(CliError::Remote("unsupported_contract_version".to_owned()));
        }
        Ok(authorization)
    }

    async fn poll(&self, proof: &DeviceProof<'_>) -> Result<DevicePoll> {
        let response = self
            .client
            .post(self.url("device/poll")?)
            .json(&PollBody {
                authorization_id: proof.authorization_id,
                device_secret: proof.device_secret.expose_secret(),
                pkce_verifier: proof.pkce_verifier.expose_secret(),
            })
            .send()
            .await
            .map_err(|_| CliError::Remote("device_poll_unavailable".to_owned()))?;
        match response.status() {
            StatusCode::ACCEPTED => Ok(DevicePoll::Pending),
            StatusCode::GONE => Ok(DevicePoll::Expired),
            StatusCode::CONFLICT | StatusCode::FORBIDDEN => Ok(DevicePoll::Denied),
            status if status.is_success() => {
                let credentials: DeviceCredentials = response
                    .json()
                    .await
                    .map_err(|_| CliError::Remote("device_poll_malformed".to_owned()))?;
                if credentials.contract_version != CONTRACT_VERSION {
                    return Err(CliError::Remote("unsupported_contract_version".to_owned()));
                }
                Ok(DevicePoll::Issued(credentials))
            }
            status => {
                let safe = response.json::<StateBody>().await.ok();
                let code = safe
                    .and_then(|body| body.error.or(body.state))
                    .filter(|value| {
                        value
                            .chars()
                            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
                    })
                    .unwrap_or_else(|| format!("http_{}", status.as_u16()));
                Err(CliError::Remote(code))
            }
        }
    }

    async fn refresh(&self, refresh: &SecretString) -> Result<DeviceCredentials> {
        let response = self
            .client
            .post(self.url("device/refresh")?)
            .json(&RefreshBody {
                refresh_token: refresh.expose_secret(),
            })
            .send()
            .await
            .map_err(|_| CliError::Remote("device_refresh_unavailable".to_owned()))?;
        if !response.status().is_success() {
            return Err(CliError::PentagonAuthorizationRequired);
        }
        let credentials: DeviceCredentials = response
            .json()
            .await
            .map_err(|_| CliError::Remote("device_refresh_malformed".to_owned()))?;
        if credentials.contract_version != CONTRACT_VERSION {
            return Err(CliError::Remote("unsupported_contract_version".to_owned()));
        }
        Ok(credentials)
    }
}

#[async_trait]
impl DeviceRevocationApi for HttpPentagonApi {
    async fn revoke_device(&self, access: &SecretString, device_id: Uuid) -> Result<()> {
        let response = self
            .client
            .post(self.url("device/revoke")?)
            .bearer_auth(access.expose_secret())
            .json(&serde_json::json!({
                "contract_version": CONTRACT_VERSION,
                "device_id": device_id,
            }))
            .send()
            .await
            .map_err(|_| CliError::Remote("device_revoke_unavailable".to_owned()))?;
        if !response.status().is_success() {
            return Err(Self::safe_error(response).await);
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
pub struct AgentSummary {
    pub agent_id: Uuid,
    pub name: String,
    pub model: String,
    pub color: String,
    #[serde(default = "default_agent_emoji")]
    pub emoji: String,
    pub execution_mode: String,
}

fn default_agent_emoji() -> String {
    "🤖".to_owned()
}

#[derive(Debug, Deserialize)]
struct AgentListResponse {
    contract_version: u8,
    agents: Vec<AgentSummary>,
}

#[derive(Serialize)]
struct CreateAgentBody<'a> {
    contract_version: u8,
    name: &'a str,
    model: Option<&'a str>,
    color: Option<&'a str>,
    instructions: Option<&'a str>,
}

pub struct CreateAgentRequest<'a> {
    pub name: &'a str,
    pub model: Option<&'a str>,
    pub color: Option<&'a str>,
    pub instructions: Option<&'a str>,
}

#[async_trait]
pub trait AgentApi: Send + Sync {
    async fn list_agents(&self, access: &SecretString) -> Result<Vec<AgentSummary>>;
    async fn create_agent(
        &self,
        access: &SecretString,
        request: &CreateAgentRequest<'_>,
    ) -> Result<AgentSummary>;
}

#[async_trait]
impl AgentApi for HttpPentagonApi {
    async fn list_agents(&self, access: &SecretString) -> Result<Vec<AgentSummary>> {
        let response = self
            .client
            .get(self.url("agents")?)
            .bearer_auth(access.expose_secret())
            .send()
            .await
            .map_err(|_| CliError::Remote("agent_list_unavailable".to_owned()))?;
        if !response.status().is_success() {
            return Err(Self::safe_error(response).await);
        }
        let body: AgentListResponse = response
            .json()
            .await
            .map_err(|_| CliError::Remote("agent_list_malformed".to_owned()))?;
        if body.contract_version != CONTRACT_VERSION {
            return Err(CliError::Remote("unsupported_contract_version".to_owned()));
        }
        Ok(body.agents)
    }

    async fn create_agent(
        &self,
        access: &SecretString,
        request: &CreateAgentRequest<'_>,
    ) -> Result<AgentSummary> {
        let response = self
            .client
            .post(self.url("agents/create")?)
            .bearer_auth(access.expose_secret())
            .json(&CreateAgentBody {
                contract_version: CONTRACT_VERSION,
                name: request.name,
                model: request.model,
                color: request.color,
                instructions: request.instructions,
            })
            .send()
            .await
            .map_err(|_| CliError::Remote("agent_create_unavailable".to_owned()))?;
        if !response.status().is_success() {
            return Err(Self::safe_error(response).await);
        }
        let agent: AgentSummary = response
            .json()
            .await
            .map_err(|_| CliError::Remote("agent_create_malformed".to_owned()))?;
        Ok(agent)
    }
}

#[derive(Debug, Deserialize)]
pub struct ProvisioningSession {
    pub contract_version: u8,
    pub session_id: Uuid,
    pub agent_id: Uuid,
    pub state: String,
    pub state_version: u32,
    pub slack_app_id: Option<String>,
    pub expected_slack_team_id: Option<String>,
    pub registration_nonce: Option<SecretString>,
    pub bootstrap_manifest: Option<Value>,
    pub desired_manifest: Option<Value>,
    pub desired_manifest_version: u32,
    pub desired_manifest_hash: String,
    pub observed_manifest_hash: Option<String>,
    pub oauth_url: Option<Url>,
    pub expires_at: String,
    pub safe_error_code: Option<String>,
}

pub struct CreateSessionRequest<'a> {
    pub agent_id: Uuid,
    pub idempotency_key: &'a str,
    pub background_color: &'a str,
    pub slack_team_id: &'a str,
}

pub struct RegisterAppRequest<'a> {
    pub session_id: Uuid,
    pub registration_nonce: &'a SecretString,
    pub slack_app_id: &'a str,
    pub slack_client_id: &'a str,
    pub slack_client_secret: &'a SecretString,
    pub slack_signing_secret: &'a SecretString,
}

#[async_trait]
pub trait ProvisioningApi: Send + Sync {
    async fn create_session(
        &self,
        access: &SecretString,
        request: &CreateSessionRequest<'_>,
    ) -> Result<ProvisioningSession>;
    async fn mark_create_unknown(
        &self,
        access: &SecretString,
        session_id: Uuid,
    ) -> Result<ProvisioningSession>;
    async fn register_app(
        &self,
        access: &SecretString,
        request: &RegisterAppRequest<'_>,
    ) -> Result<ProvisioningSession>;
    async fn manifest_receipt(
        &self,
        access: &SecretString,
        session_id: Uuid,
        hash: &str,
        version: u32,
        permissions_updated: bool,
    ) -> Result<ProvisioningSession>;
    async fn session(&self, access: &SecretString, session_id: Uuid)
    -> Result<ProvisioningSession>;
    async fn session_for_agent(
        &self,
        access: &SecretString,
        agent_id: Uuid,
    ) -> Result<ProvisioningSession>;
}

#[derive(Serialize)]
struct CreateSessionBody<'a> {
    contract_version: u8,
    agent_id: Uuid,
    idempotency_key: &'a str,
    background_color: &'a str,
    slack_team_id: &'a str,
}

#[derive(Serialize)]
struct RegisterAppBody<'a> {
    contract_version: u8,
    registration_nonce: &'a str,
    slack_app_id: &'a str,
    slack_client_id: &'a str,
    slack_client_secret: &'a str,
    slack_signing_secret: &'a str,
}

#[derive(Serialize)]
struct ManifestReceiptBody<'a> {
    contract_version: u8,
    observed_manifest_hash: &'a str,
    manifest_version: u32,
    permissions_updated: bool,
}

impl HttpPentagonApi {
    async fn checked_session(&self, response: reqwest::Response) -> Result<ProvisioningSession> {
        if !response.status().is_success() {
            return Err(Self::safe_error(response).await);
        }
        let session: ProvisioningSession = response
            .json()
            .await
            .map_err(|_| CliError::Remote("provisioning_response_malformed".to_owned()))?;
        if session.contract_version != CONTRACT_VERSION {
            return Err(CliError::Remote("unsupported_contract_version".to_owned()));
        }
        Ok(session)
    }
}

#[async_trait]
impl ProvisioningApi for HttpPentagonApi {
    async fn create_session(
        &self,
        access: &SecretString,
        request: &CreateSessionRequest<'_>,
    ) -> Result<ProvisioningSession> {
        let response = self
            .client
            .post(self.url("slack/sessions")?)
            .bearer_auth(access.expose_secret())
            .json(&CreateSessionBody {
                contract_version: CONTRACT_VERSION,
                agent_id: request.agent_id,
                idempotency_key: request.idempotency_key,
                background_color: request.background_color,
                slack_team_id: request.slack_team_id,
            })
            .send()
            .await
            .map_err(|_| CliError::Remote("session_create_unavailable".to_owned()))?;
        self.checked_session(response).await
    }

    async fn mark_create_unknown(
        &self,
        access: &SecretString,
        session_id: Uuid,
    ) -> Result<ProvisioningSession> {
        let response = self
            .client
            .post(self.url(&format!("slack/sessions/{session_id}/create-unknown"))?)
            .bearer_auth(access.expose_secret())
            .json(&serde_json::json!({ "contract_version": CONTRACT_VERSION }))
            .send()
            .await
            .map_err(|_| CliError::Remote("session_update_unavailable".to_owned()))?;
        self.checked_session(response).await
    }

    async fn register_app(
        &self,
        access: &SecretString,
        request: &RegisterAppRequest<'_>,
    ) -> Result<ProvisioningSession> {
        let response = self
            .client
            .post(self.url(&format!(
                "slack/sessions/{}/register-app",
                request.session_id
            ))?)
            .bearer_auth(access.expose_secret())
            .json(&RegisterAppBody {
                contract_version: CONTRACT_VERSION,
                registration_nonce: request.registration_nonce.expose_secret(),
                slack_app_id: request.slack_app_id,
                slack_client_id: request.slack_client_id,
                slack_client_secret: request.slack_client_secret.expose_secret(),
                slack_signing_secret: request.slack_signing_secret.expose_secret(),
            })
            .send()
            .await
            .map_err(|_| CliError::Remote("app_registration_unavailable".to_owned()))?;
        self.checked_session(response).await
    }

    async fn manifest_receipt(
        &self,
        access: &SecretString,
        session_id: Uuid,
        hash: &str,
        version: u32,
        permissions_updated: bool,
    ) -> Result<ProvisioningSession> {
        let response = self
            .client
            .post(self.url(&format!("slack/sessions/{session_id}/manifest-receipt"))?)
            .bearer_auth(access.expose_secret())
            .json(&ManifestReceiptBody {
                contract_version: CONTRACT_VERSION,
                observed_manifest_hash: hash,
                manifest_version: version,
                permissions_updated,
            })
            .send()
            .await
            .map_err(|_| CliError::Remote("manifest_receipt_unavailable".to_owned()))?;
        self.checked_session(response).await
    }

    async fn session(
        &self,
        access: &SecretString,
        session_id: Uuid,
    ) -> Result<ProvisioningSession> {
        let response = self
            .client
            .get(self.url(&format!("slack/sessions/{session_id}"))?)
            .bearer_auth(access.expose_secret())
            .send()
            .await
            .map_err(|_| CliError::Remote("session_status_unavailable".to_owned()))?;
        self.checked_session(response).await
    }

    async fn session_for_agent(
        &self,
        access: &SecretString,
        agent_id: Uuid,
    ) -> Result<ProvisioningSession> {
        let response = self
            .client
            .get(self.url(&format!("slack/agents/{agent_id}"))?)
            .bearer_auth(access.expose_secret())
            .send()
            .await
            .map_err(|_| CliError::Remote("agent_slack_status_unavailable".to_owned()))?;
        self.checked_session(response).await
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        sync::mpsc,
    };

    use secrecy::SecretString;
    use uuid::Uuid;

    use super::{
        AgentApi, CreateAgentRequest, CreateSessionRequest, HttpPentagonApi, OrganizationEndpoint,
        ProvisioningApi, allowed_local_api_override,
    };
    use url::Url;

    fn one_response(body: &str) -> (Url, mpsc::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (send, receive) = mpsc::channel();
        let response_body = body.to_owned();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut bytes = Vec::new();
            let mut buffer = [0_u8; 4096];
            loop {
                let count = stream.read(&mut buffer).unwrap();
                if count == 0 {
                    break;
                }
                bytes.extend_from_slice(&buffer[..count]);
                if String::from_utf8_lossy(&bytes).contains("\r\n\r\n") {
                    break;
                }
            }
            send.send(String::from_utf8_lossy(&bytes).to_string())
                .unwrap();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            )
            .unwrap();
        });
        (Url::parse(&format!("http://{address}/")).unwrap(), receive)
    }

    #[test]
    fn resolves_any_valid_organization_to_its_pentagon_endpoint() {
        let endpoint = OrganizationEndpoint::resolve("example-org").unwrap();
        assert_eq!(endpoint.slug, "example-org");
        assert_eq!(
            endpoint.base_url.as_str(),
            "https://example-org.pentagon.run/api/cli/"
        );
        assert!(OrganizationEndpoint::resolve("invalid_org").is_err());
    }

    #[test]
    fn namespaces_keychain_accounts_by_origin_port_and_org() {
        let endpoint = OrganizationEndpoint::resolve("example-org").unwrap();
        let account = endpoint.keychain_account();
        assert!(account.contains("example-org.pentagon.run:443:example-org"));
        assert!(!account.contains("token"));
    }

    #[test]
    fn local_override_accepts_only_http_or_https_loopback() {
        assert!(allowed_local_api_override(
            &Url::parse("http://127.0.0.1:54321/").unwrap()
        ));
        assert!(allowed_local_api_override(
            &Url::parse("https://localhost:54321/").unwrap()
        ));
        assert!(allowed_local_api_override(
            &Url::parse("http://[::1]:54321/").unwrap()
        ));
        assert!(!allowed_local_api_override(
            &Url::parse("https://example.test/").unwrap()
        ));
        assert!(!allowed_local_api_override(
            &Url::parse("http://example.test/").unwrap()
        ));
        assert!(!allowed_local_api_override(
            &Url::parse("ftp://127.0.0.1/").unwrap()
        ));
    }

    #[tokio::test]
    async fn agent_creation_serializes_the_canonical_configuration() {
        let agent_id = Uuid::from_u128(3);
        let (base_url, request) = one_response(&format!(
            r##"{{"agent_id":"{agent_id}","name":"Treasury","model":"openai/gpt-5.6-terra","color":"#123abc","emoji":"🤖","execution_mode":"cloud"}}"##,
        ));
        let api = HttpPentagonApi::new(OrganizationEndpoint {
            slug: "example-org".to_owned(),
            base_url,
        })
        .unwrap();

        let created = api
            .create_agent(
                &SecretString::from("pga_test"),
                &CreateAgentRequest {
                    name: "Treasury",
                    model: Some("openai/gpt-5.6-terra"),
                    color: Some("#123abc"),
                    instructions: Some("Keep reconciliations current."),
                },
            )
            .await
            .unwrap();

        assert_eq!(created.agent_id, agent_id);
        let request = request.recv().unwrap();
        assert!(request.starts_with("POST /agents/create HTTP/1.1"));
        assert!(request.contains(r#""model":"openai/gpt-5.6-terra""#));
        assert!(request.contains(r##""color":"#123abc""##));
        assert!(request.contains(r#""instructions":"Keep reconciliations current.""#));
    }

    #[tokio::test]
    async fn session_discovery_is_a_read_only_agent_lookup() {
        let agent_id = Uuid::from_u128(2);
        let (base_url, request) = one_response(&format!(
            r#"{{"contract_version":1,"session_id":"00000000-0000-0000-0000-000000000001","agent_id":"{agent_id}","state":"active","state_version":5,"slack_app_id":"A123","expected_slack_team_id":"T123","registration_nonce":null,"bootstrap_manifest":null,"desired_manifest":{{}},"desired_manifest_version":1,"desired_manifest_hash":"{}","observed_manifest_hash":"{}","oauth_url":null,"expires_at":"2026-09-06T00:00:00Z","safe_error_code":null}}"#,
            "a".repeat(64),
            "a".repeat(64),
        ));
        let api = HttpPentagonApi::new(OrganizationEndpoint {
            slug: "example-org".to_owned(),
            base_url,
        })
        .unwrap();

        let session = api
            .session_for_agent(&SecretString::from("pga_test"), agent_id)
            .await
            .unwrap();

        assert_eq!(session.agent_id, agent_id);
        let request = request.recv().unwrap();
        assert!(request.starts_with(&format!("GET /slack/agents/{agent_id} HTTP/1.1")));
        assert!(!request.contains("POST "));
    }

    #[tokio::test]
    async fn session_creation_sends_only_the_observed_workspace_identifier() {
        let agent_id = Uuid::from_u128(2);
        let (base_url, request) = one_response(&format!(
            r#"{{"contract_version":1,"session_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","agent_id":"{agent_id}","state":"requested","state_version":1,"slack_app_id":null,"expected_slack_team_id":"TEXAMPLE01","registration_nonce":"nonce","bootstrap_manifest":{{}},"desired_manifest":{{}},"desired_manifest_version":1,"desired_manifest_hash":"{}","observed_manifest_hash":null,"oauth_url":null,"expires_at":"2026-09-06T00:00:00Z","safe_error_code":null}}"#,
            "a".repeat(64),
        ));
        let api = HttpPentagonApi::new(OrganizationEndpoint {
            slug: "example-org".to_owned(),
            base_url,
        })
        .unwrap();

        api.create_session(
            &SecretString::from("pga_test"),
            &CreateSessionRequest {
                agent_id,
                idempotency_key: "example-session-1234",
                background_color: "#123abc",
                slack_team_id: "TEXAMPLE01",
            },
        )
        .await
        .unwrap();

        let request = request.recv().unwrap();
        assert!(request.starts_with("POST /slack/sessions HTTP/1.1"));
        assert!(request.contains(r#""slack_team_id":"TEXAMPLE01""#));
        assert!(!request.contains("xoxe-"));
    }
}
