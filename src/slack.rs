use std::{collections::BTreeMap, time::Duration};

use async_trait::async_trait;
use reqwest::StatusCode;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use url::Url;
use uuid::Uuid;

use crate::{CliError, Result};

const SLACK_API: &str = "https://slack.com/api/";

#[derive(Debug)]
pub struct SlackConfigurationCredential {
    pub access: SecretString,
    pub refresh: SecretString,
    pub team_id: String,
    pub user_id: String,
}

#[derive(Debug)]
pub struct CreatedSlackApp {
    pub app_id: String,
    pub client_id: String,
    pub client_secret: SecretString,
    pub signing_secret: SecretString,
}

#[derive(Debug)]
pub struct ManifestUpdate {
    pub permissions_updated: bool,
}

#[async_trait]
pub trait SlackProvisioningApi: Send + Sync {
    async fn validate(
        &self,
        access: &SecretString,
        app_id: Option<&str>,
        manifest: &Value,
    ) -> Result<()>;
    async fn create(&self, access: &SecretString, manifest: &Value) -> Result<CreatedSlackApp>;
    async fn update(
        &self,
        access: &SecretString,
        app_id: &str,
        manifest: &Value,
    ) -> Result<ManifestUpdate>;
    async fn export(&self, access: &SecretString, app_id: &str) -> Result<Value>;
    async fn set_icon(&self, access: &SecretString, app_id: &str, png: Vec<u8>) -> Result<()>;
    async fn wait_for_event_ingress(&self, manifest: &Value) -> Result<()>;
}

#[derive(Debug, Deserialize)]
struct SlackEnvelope {
    ok: bool,
    error: Option<String>,
    token: Option<SecretString>,
    refresh_token: Option<SecretString>,
    team_id: Option<String>,
    user_id: Option<String>,
    app_id: Option<String>,
    credentials: Option<SlackAppCredentials>,
    manifest: Option<Value>,
    permissions_updated: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct SlackAppCredentials {
    client_id: String,
    client_secret: SecretString,
    signing_secret: SecretString,
}

pub struct SlackClient {
    client: reqwest::Client,
    base_url: String,
}

impl SlackClient {
    pub fn new() -> Result<Self> {
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .user_agent(concat!("pentagon-cli/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|_| CliError::Remote("slack_client_initialization_failed".to_owned()))?;
        Ok(Self {
            client,
            base_url: SLACK_API.to_owned(),
        })
    }

    #[cfg(test)]
    fn with_base_url(base_url: String) -> Result<Self> {
        let mut client = Self::new()?;
        client.base_url = base_url;
        Ok(client)
    }

    async fn response(
        &self,
        request: reqwest::RequestBuilder,
        operation: &'static str,
    ) -> Result<SlackEnvelope> {
        let mut attempt = 0_u8;
        let response = loop {
            attempt += 1;
            let pending = request.try_clone().ok_or_else(|| {
                CliError::Remote(format!("slack_{operation}_request_not_replayable"))
            })?;
            let response = pending.send().await.map_err(|_| {
                if operation == "manifest_create" {
                    CliError::CreateOutcomeUnknown
                } else {
                    CliError::Remote(format!("slack_{operation}_unavailable"))
                }
            })?;
            if response.status() != StatusCode::TOO_MANY_REQUESTS || attempt >= 3 {
                break response;
            }
            let retry_after = response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(1)
                .clamp(1, 60);
            tokio::time::sleep(Duration::from_secs(retry_after)).await;
        };
        let status = response.status();
        let envelope = response.json::<SlackEnvelope>().await.map_err(|_| {
            if operation == "manifest_create" {
                CliError::CreateOutcomeUnknown
            } else {
                CliError::Remote(format!("slack_{operation}_malformed"))
            }
        })?;
        if status.is_success() && envelope.ok {
            return Ok(envelope);
        }
        let code = envelope
            .error
            .as_deref()
            .filter(|value| {
                value
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
            })
            .unwrap_or("unknown_error");
        if operation == "manifest_create"
            && (status.is_server_error()
                || matches!(
                    code,
                    "fatal_error" | "internal_error" | "request_timeout" | "service_unavailable"
                ))
        {
            return Err(CliError::CreateOutcomeUnknown);
        }
        if status == StatusCode::TOO_MANY_REQUESTS || code == "ratelimited" {
            return Err(CliError::Remote("slack_rate_limited".to_owned()));
        }
        Err(CliError::Remote(format!("slack_{operation}_{code}")))
    }

    pub async fn rotate(&self, refresh: &SecretString) -> Result<SlackConfigurationCredential> {
        let envelope = self
            .response(
                self.client
                    .post(format!("{}tooling.tokens.rotate", self.base_url))
                    .form(&[("refresh_token", refresh.expose_secret())]),
                "configuration_token_rotate",
            )
            .await?;
        let access = envelope.token.ok_or_else(|| {
            CliError::Remote("slack_configuration_token_rotate_malformed".to_owned())
        })?;
        let next_refresh = envelope.refresh_token.ok_or_else(|| {
            CliError::Remote("slack_configuration_token_rotate_malformed".to_owned())
        })?;
        let team_id = envelope.team_id.filter(|id| slack_id(id, Some('T')));
        let user_id = envelope.user_id.filter(|id| slack_id(id, None));
        match (team_id, user_id) {
            (Some(team_id), Some(user_id)) => Ok(SlackConfigurationCredential {
                access,
                refresh: next_refresh,
                team_id,
                user_id,
            }),
            _ => Err(CliError::Remote(
                "slack_configuration_token_rotate_malformed".to_owned(),
            )),
        }
    }

    pub async fn validate(
        &self,
        access: &SecretString,
        app_id: Option<&str>,
        manifest: &Value,
    ) -> Result<()> {
        let mut body = json!({
            "manifest": serde_json::to_string(manifest)
                .map_err(|_| CliError::InvalidInput("manifest cannot be serialized"))?
        });
        if let Some(app_id) = app_id {
            body["app_id"] = Value::String(app_id.to_owned());
        }
        self.response(
            self.client
                .post(format!("{}apps.manifest.validate", self.base_url))
                .bearer_auth(access.expose_secret())
                .json(&body),
            "manifest_validate",
        )
        .await
        .map(|_| ())
    }

    pub async fn create(&self, access: &SecretString, manifest: &Value) -> Result<CreatedSlackApp> {
        let envelope = self.response(
            self.client.post(format!("{}apps.manifest.create", self.base_url))
                .bearer_auth(access.expose_secret())
                .json(&json!({ "manifest": serde_json::to_string(manifest).map_err(|_| CliError::InvalidInput("manifest cannot be serialized"))? })),
            "manifest_create",
        ).await?;
        let app_id = envelope.app_id.filter(|id| {
            id.chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
        });
        match (app_id, envelope.credentials) {
            (Some(app_id), Some(credentials)) if credentials.client_id.contains('.') => {
                Ok(CreatedSlackApp {
                    app_id,
                    client_id: credentials.client_id,
                    client_secret: credentials.client_secret,
                    signing_secret: credentials.signing_secret,
                })
            }
            _ => Err(CliError::CreateOutcomeUnknown),
        }
    }

    pub async fn update(
        &self,
        access: &SecretString,
        app_id: &str,
        manifest: &Value,
    ) -> Result<ManifestUpdate> {
        let envelope = self.response(
            self.client.post(format!("{}apps.manifest.update", self.base_url))
                .bearer_auth(access.expose_secret())
                .json(&json!({ "app_id": app_id, "manifest": serde_json::to_string(manifest).map_err(|_| CliError::InvalidInput("manifest cannot be serialized"))? })),
            "manifest_update",
        ).await?;
        Ok(ManifestUpdate {
            permissions_updated: envelope.permissions_updated.unwrap_or(false),
        })
    }

    pub async fn export(&self, access: &SecretString, app_id: &str) -> Result<Value> {
        self.response(
            self.client
                .post(format!("{}apps.manifest.export", self.base_url))
                .bearer_auth(access.expose_secret())
                .json(&json!({ "app_id": app_id })),
            "manifest_export",
        )
        .await?
        .manifest
        .ok_or_else(|| CliError::Remote("slack_manifest_export_malformed".to_owned()))
    }

    pub async fn set_icon(&self, access: &SecretString, app_id: &str, png: Vec<u8>) -> Result<()> {
        for attempt in 1..=3 {
            let part = reqwest::multipart::Part::bytes(png.clone())
                .file_name("pentagon-agent.png")
                .mime_str("image/png")
                .map_err(|_| CliError::InvalidInput("invalid icon payload"))?;
            let response = self
                .client
                .post(format!("{}apps.icon.set", self.base_url))
                .bearer_auth(access.expose_secret())
                .multipart(
                    reqwest::multipart::Form::new()
                        .text("app_id", app_id.to_owned())
                        .part("file", part),
                )
                .send()
                .await
                .map_err(|_| CliError::Remote("slack_icon_set_unavailable".to_owned()))?;
            if response.status() == StatusCode::TOO_MANY_REQUESTS && attempt < 3 {
                let retry_after = response
                    .headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.parse::<u64>().ok())
                    .unwrap_or(1)
                    .clamp(1, 60);
                tokio::time::sleep(Duration::from_secs(retry_after)).await;
                continue;
            }
            let status = response.status();
            let envelope = response
                .json::<SlackEnvelope>()
                .await
                .map_err(|_| CliError::Remote("slack_icon_set_malformed".to_owned()))?;
            if status.is_success() && envelope.ok {
                return Ok(());
            }
            let code = envelope
                .error
                .as_deref()
                .filter(|value| {
                    value
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
                })
                .unwrap_or("unknown_error");
            return Err(CliError::Remote(format!("slack_icon_set_{code}")));
        }
        Err(CliError::Remote("slack_icon_set_rate_limited".to_owned()))
    }

    pub async fn wait_for_event_ingress(&self, manifest: &Value) -> Result<()> {
        let raw = manifest
            .pointer("/settings/event_subscriptions/request_url")
            .and_then(Value::as_str)
            .ok_or_else(|| CliError::Remote("slack_event_request_url_missing".to_owned()))?;
        let url = Url::parse(raw)
            .map_err(|_| CliError::Remote("slack_event_request_url_invalid".to_owned()))?;
        let secure = url.scheme() == "https"
            && url.username().is_empty()
            && url.password().is_none()
            && url.host_str().is_some();
        #[cfg(test)]
        let secure = secure
            || (url.scheme() == "http"
                && matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "::1")));
        if !secure {
            return Err(CliError::Remote(
                "slack_event_request_url_invalid".to_owned(),
            ));
        }

        let challenge = format!("pentagon-cli-{}", Uuid::new_v4());
        for attempt in 1..=8_u64 {
            let response = self
                .client
                .post(url.clone())
                .timeout(Duration::from_secs(5))
                .json(&json!({
                    "type": "url_verification",
                    "challenge": challenge,
                }))
                .send()
                .await;
            if let Ok(response) = response
                && response.status().is_success()
            {
                let echoed = response.json::<Value>().await.ok().and_then(|body| {
                    body.get("challenge")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                });
                if echoed.as_deref() == Some(challenge.as_str()) {
                    return Ok(());
                }
            }
            if attempt < 8 {
                tokio::time::sleep(Duration::from_secs(attempt.min(3))).await;
            }
        }
        Err(CliError::Remote(
            "slack_event_request_url_unavailable".to_owned(),
        ))
    }
}

#[async_trait]
impl SlackProvisioningApi for SlackClient {
    async fn validate(
        &self,
        access: &SecretString,
        app_id: Option<&str>,
        manifest: &Value,
    ) -> Result<()> {
        SlackClient::validate(self, access, app_id, manifest).await
    }
    async fn create(&self, access: &SecretString, manifest: &Value) -> Result<CreatedSlackApp> {
        SlackClient::create(self, access, manifest).await
    }
    async fn update(
        &self,
        access: &SecretString,
        app_id: &str,
        manifest: &Value,
    ) -> Result<ManifestUpdate> {
        SlackClient::update(self, access, app_id, manifest).await
    }
    async fn export(&self, access: &SecretString, app_id: &str) -> Result<Value> {
        SlackClient::export(self, access, app_id).await
    }
    async fn set_icon(&self, access: &SecretString, app_id: &str, png: Vec<u8>) -> Result<()> {
        SlackClient::set_icon(self, access, app_id, png).await
    }
    async fn wait_for_event_ingress(&self, manifest: &Value) -> Result<()> {
        SlackClient::wait_for_event_ingress(self, manifest).await
    }
}

pub fn managed_manifest_hash(value: &Value) -> String {
    let projection = json!({
        "features": {
            "app_home": {
                "messages_tab_enabled": pointer_bool(value, "/features/app_home/messages_tab_enabled"),
                "messages_tab_read_only_enabled": pointer_bool(value, "/features/app_home/messages_tab_read_only_enabled"),
            },
            "agent_view": value.pointer("/features/agent_view").cloned().unwrap_or_else(|| json!({})),
        },
        "oauth_config": {
            "redirect_urls": sorted_strings(value.pointer("/oauth_config/redirect_urls")),
            "scopes": {
                "bot": sorted_strings(value.pointer("/oauth_config/scopes/bot")),
                "user": sorted_strings(value.pointer("/oauth_config/scopes/user")),
            },
        },
        "settings": {
            "interactivity": {
                "is_enabled": pointer_bool(value, "/settings/interactivity/is_enabled"),
                "request_url": pointer_string(value, "/settings/interactivity/request_url"),
            },
            "event_subscriptions": {
                "request_url": pointer_string(value, "/settings/event_subscriptions/request_url"),
                "bot_events": sorted_strings(value.pointer("/settings/event_subscriptions/bot_events")),
            },
        },
    });
    let canonical = canonical_value(&projection);
    let digest =
        Sha256::digest(serde_json::to_vec(&canonical).expect("JSON projection serializes"));
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn pointer_bool(value: &Value, pointer: &str) -> bool {
    value
        .pointer(pointer)
        .and_then(Value::as_bool)
        .unwrap_or(false)
}
fn slack_id(value: &str, prefix: Option<char>) -> bool {
    (2..=32).contains(&value.len())
        && prefix.is_none_or(|expected| value.starts_with(expected))
        && value
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
}
fn pointer_string(value: &Value, pointer: &str) -> Value {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .map_or(Value::Null, |v| Value::String(v.to_owned()))
}
fn sorted_strings(value: Option<&Value>) -> Vec<String> {
    let mut values = value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    values.sort();
    values.dedup();
    values
}
fn canonical_value(value: &Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.iter().map(canonical_value).collect()),
        Value::Object(values) => {
            let ordered = values
                .iter()
                .map(|(key, value)| (key.clone(), canonical_value(value)))
                .collect::<BTreeMap<_, _>>();
            Value::Object(ordered.into_iter().collect::<Map<_, _>>())
        }
        _ => value.clone(),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        sync::mpsc,
    };

    use secrecy::{ExposeSecret, SecretString};

    use super::{SLACK_API, SlackClient, managed_manifest_hash};
    use crate::CliError;
    use serde_json::{Value, json};

    #[test]
    fn canonical_hash_ignores_unowned_fields_and_order() {
        let one = json!({
            "display_information": { "name": "ignored" },
            "features": { "app_home": { "messages_tab_enabled": true }, "agent_view": { "suggested_prompts": [{"title":"A"}] } },
            "oauth_config": { "redirect_urls": ["https://b", "https://a"], "scopes": { "bot": ["chat:write", "app_mentions:read"], "user": [] } },
            "settings": { "interactivity": { "is_enabled": true, "request_url": "https://actions" }, "event_subscriptions": { "request_url": "https://events", "bot_events": ["message.im", "app_mention"] } }
        });
        let mut two = one.clone();
        two["display_information"]["name"] = json!("human edit");
        two["oauth_config"]["scopes"]["bot"] = json!(["app_mentions:read", "chat:write"]);
        assert_eq!(managed_manifest_hash(&one), managed_manifest_hash(&two));
        assert_eq!(
            managed_manifest_hash(&one),
            "972d7a0c5e210a12ee84059da9fd0997b40a5d44b4028d53246915682134f2ad"
        );
    }

    #[test]
    fn production_client_pins_slack_credentials_to_slack() {
        assert_eq!(SlackClient::new().unwrap().base_url, SLACK_API);
    }

    fn one_response(status: &str, body: &str) -> (String, mpsc::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (send, receive) = mpsc::channel();
        let response_body = body.to_owned();
        let response_status = status.to_owned();
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
                let text = String::from_utf8_lossy(&bytes);
                let headers_end = text.find("\r\n\r\n");
                let length = text
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length: ")
                            .and_then(|value| value.trim().parse::<usize>().ok())
                    })
                    .unwrap_or(0);
                if headers_end.is_some_and(|end| bytes.len() >= end + 4 + length) {
                    break;
                }
            }
            send.send(String::from_utf8_lossy(&bytes).to_string())
                .unwrap();
            write!(stream, "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", response_status, response_body.len(), response_body).unwrap();
        });
        (format!("http://{address}/"), receive)
    }

    #[tokio::test]
    async fn ambiguous_create_is_never_retried() {
        let (base, request) = one_response(
            "500 Internal Server Error",
            r#"{"ok":false,"error":"internal_error"}"#,
        );
        let client = SlackClient::with_base_url(base).unwrap();
        let result = client
            .create(
                &SecretString::from("xoxe.xoxp-local"),
                &json!({ "display_information": { "name": "Test" } }),
            )
            .await;
        assert!(matches!(result, Err(CliError::CreateOutcomeUnknown)));
        let request = request.recv().unwrap();
        assert_eq!(request.matches("POST ").count(), 1);
    }

    #[tokio::test]
    async fn event_ingress_is_warmed_without_transmitting_slack_credentials() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (send, receive) = mpsc::channel();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut bytes = Vec::new();
            let mut buffer = [0_u8; 4096];
            loop {
                let count = stream.read(&mut buffer).unwrap();
                bytes.extend_from_slice(&buffer[..count]);
                let text = String::from_utf8_lossy(&bytes);
                let headers_end = text.find("\r\n\r\n");
                let length = text
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length: ")
                            .and_then(|value| value.trim().parse::<usize>().ok())
                    })
                    .unwrap_or(0);
                if count == 0 || headers_end.is_some_and(|end| bytes.len() >= end + 4 + length) {
                    break;
                }
            }
            let raw = String::from_utf8_lossy(&bytes).to_string();
            let challenge = raw
                .split("\r\n\r\n")
                .nth(1)
                .and_then(|body| serde_json::from_str::<serde_json::Value>(body).ok())
                .and_then(|body| {
                    body.get("challenge")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                })
                .unwrap();
            send.send(raw).unwrap();
            let body = json!({ "challenge": challenge }).to_string();
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).unwrap();
        });
        let client = SlackClient::new().unwrap();
        client
            .wait_for_event_ingress(&json!({
                "settings": {
                    "event_subscriptions": {
                        "request_url": format!("http://{address}/events")
                    }
                }
            }))
            .await
            .unwrap();

        let request = receive.recv().unwrap();
        assert!(request.starts_with("POST /events HTTP/1.1"));
        assert!(request.contains(r#""type":"url_verification""#));
        assert!(!request.to_ascii_lowercase().contains("authorization:"));
        assert!(!request.contains("xoxe"));
    }

    #[tokio::test]
    async fn event_ingress_rejects_non_https_non_loopback_urls() {
        let client = SlackClient::new().unwrap();
        let error = client
            .wait_for_event_ingress(&json!({
                "settings": { "event_subscriptions": { "request_url": "http://example.test/events" } }
            }))
            .await
            .unwrap_err();
        assert!(
            matches!(error, CliError::Remote(ref code) if code == "slack_event_request_url_invalid")
        );
    }

    #[tokio::test]
    async fn configuration_rotation_uses_form_input_and_accepts_only_bounded_identity() {
        let (base, request) = one_response(
            "200 OK",
            r#"{"ok":true,"token":"xoxe.xoxp-access","refresh_token":"xoxe-next","team_id":"T123","user_id":"U123"}"#,
        );
        let client = SlackClient::with_base_url(base).unwrap();
        let rotated = client
            .rotate(&SecretString::from("xoxe-old"))
            .await
            .unwrap();
        assert_eq!(rotated.team_id, "T123");
        assert_eq!(rotated.refresh.expose_secret(), "xoxe-next");
        let request = request.recv().unwrap();
        assert!(request.contains("refresh_token=xoxe-old"));
        assert!(!format!("{rotated:?}").contains("xoxe-next"));
    }

    #[tokio::test]
    async fn icon_upload_is_a_replayable_bounded_multipart_request() {
        let (base, request) = one_response("200 OK", r#"{"ok":true}"#);
        let client = SlackClient::with_base_url(base).unwrap();
        client
            .set_icon(
                &SecretString::from("xoxe.xoxp-access"),
                "A123",
                b"fake-png".to_vec(),
            )
            .await
            .unwrap();
        let request = request.recv().unwrap();
        assert!(request.contains("POST /apps.icon.set"));
        assert!(request.contains("name=\"app_id\""));
        assert!(request.contains("A123"));
        assert!(request.contains("name=\"file\""));
    }
}
