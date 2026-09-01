use std::{
    io::Cursor,
    time::{Duration, Instant},
};

use secrecy::SecretString;
use uuid::Uuid;

use crate::{
    CliError, Result,
    api::{CreateSessionRequest, ProvisioningApi, ProvisioningSession, RegisterAppRequest},
    auth::Browser,
    journal::{Journal, JournalEntry},
    slack::{SlackProvisioningApi, managed_manifest_hash},
};

// Byte-for-byte output from Pentagon's SwiftUI Slack avatar renderer for the
// default agent appearance: `🤖` at 236 pt over `#35425a`, rendered at 512 px.
const DEFAULT_AGENT_AVATAR_PNG: &[u8] = include_bytes!("../assets/default-agent-avatar.png");
const AVATAR_TEMPLATE_COLOR: &str = "#35425a";

#[derive(Debug)]
pub struct ProvisionReceipt {
    pub session_id: Uuid,
    pub app_id: String,
    pub state: String,
}

#[allow(clippy::too_many_arguments)]
pub async fn provision_slack(
    pentagon: &dyn ProvisioningApi,
    access: &SecretString,
    slack: &dyn SlackProvisioningApi,
    slack_access: &SecretString,
    agent_id: Uuid,
    agent_color: &str,
    observed_team_id: &str,
    browser: &dyn Browser,
    journal: &mut Journal,
) -> Result<ProvisionReceipt> {
    let prior = journal.get(agent_id).cloned();
    let session = if let Some(entry) = &prior {
        pentagon.session(access, entry.session_id).await?
    } else {
        let idempotency = format!("slack-create:{}", Uuid::new_v4());
        pentagon
            .create_session(
                access,
                &CreateSessionRequest {
                    agent_id,
                    idempotency_key: &idempotency,
                    background_color: agent_color,
                    slack_team_id: observed_team_id,
                },
            )
            .await?
    };
    let known_app_id = session
        .slack_app_id
        .clone()
        .or_else(|| prior.as_ref().and_then(|entry| entry.app_id.clone()));
    journal.record(JournalEntry {
        session_id: session.session_id,
        agent_id,
        app_id: known_app_id.clone(),
        state: session.state.clone(),
    })?;
    if session.expected_slack_team_id.as_deref() != Some(observed_team_id) {
        return Err(CliError::WrongSlackWorkspace);
    }

    match session.state.as_str() {
        "active" => {
            let app_id =
                known_app_id.ok_or_else(|| CliError::Remote("slack_app_id_missing".to_owned()))?;
            slack
                .set_icon(slack_access, &app_id, agent_avatar_png(agent_color)?)
                .await?;
            return Ok(ProvisionReceipt {
                session_id: session.session_id,
                app_id,
                state: session.state,
            });
        }
        "oauth_pending" => {
            let app_id =
                known_app_id.ok_or_else(|| CliError::Remote("slack_app_id_missing".to_owned()))?;
            let oauth_url = session.oauth_url.as_ref().map(url::Url::as_str);
            return wait_for_activation(
                pentagon, access, &session, agent_id, app_id, oauth_url, browser, journal,
            )
            .await;
        }
        "app_registered" => {
            let app_id =
                known_app_id.ok_or_else(|| CliError::Remote("slack_app_id_missing".to_owned()))?;
            return apply_manifest_and_wait(
                pentagon,
                access,
                slack,
                slack_access,
                session,
                agent_id,
                app_id,
                agent_color,
                browser,
                journal,
            )
            .await;
        }
        "create_outcome_unknown" => return Err(CliError::CreateOutcomeUnknown),
        "app_created" => {
            return Err(CliError::Remote(
                "app_registration_interrupted_delete_or_contact_support".to_owned(),
            ));
        }
        "requested" => {}
        state => {
            return Err(CliError::Remote(format!(
                "unexpected_session_state_{state}"
            )));
        }
    }

    if known_app_id.is_some() {
        return Err(CliError::Remote(
            "unregistered_slack_app_requires_exact_cleanup".to_owned(),
        ));
    }

    let bootstrap = session
        .bootstrap_manifest
        .as_ref()
        .ok_or_else(|| CliError::Remote("bootstrap_manifest_missing".to_owned()))?;
    let nonce = session
        .registration_nonce
        .as_ref()
        .ok_or_else(|| CliError::Remote("registration_nonce_missing".to_owned()))?;

    slack.validate(slack_access, None, bootstrap).await?;
    let app = match slack.create(slack_access, bootstrap).await {
        Ok(app) => app,
        Err(CliError::CreateOutcomeUnknown) => {
            let _ = pentagon
                .mark_create_unknown(access, session.session_id)
                .await;
            return Err(CliError::CreateOutcomeUnknown);
        }
        Err(error) => return Err(error),
    };
    let app_journal_result = journal.record(JournalEntry {
        session_id: session.session_id,
        agent_id,
        app_id: Some(app.app_id.clone()),
        state: "app_created".to_owned(),
    });

    let registration = RegisterAppRequest {
        session_id: session.session_id,
        registration_nonce: nonce,
        slack_app_id: &app.app_id,
        slack_client_id: &app.client_id,
        slack_client_secret: &app.client_secret,
        slack_signing_secret: &app.signing_secret,
    };
    let mut attempt = 0;
    let registered = loop {
        attempt += 1;
        match pentagon.register_app(access, &registration).await {
            Ok(registered) => break registered,
            Err(CliError::Remote(code))
                if code == "app_registration_unavailable" && attempt < 3 =>
            {
                tokio::time::sleep(Duration::from_secs(attempt)).await;
            }
            Err(error) => {
                if app_journal_result.is_err() {
                    // Neither local recovery coordinates nor a durable server
                    // registration can be proven. Fence the session so a
                    // later invocation cannot create a second Slack app.
                    let _ = pentagon
                        .mark_create_unknown(access, session.session_id)
                        .await;
                    return Err(CliError::CreateOutcomeUnknown);
                }
                return Err(error);
            }
        }
    };
    // Registration now durably identifies the exact app. Stop before more
    // mutations when the local write failed and let the next invocation
    // reconstruct the journal from Pentagon's session.
    app_journal_result?;
    journal.record(JournalEntry {
        session_id: session.session_id,
        agent_id,
        app_id: Some(app.app_id.clone()),
        state: registered.state,
    })?;

    apply_manifest_and_wait(
        pentagon,
        access,
        slack,
        slack_access,
        session,
        agent_id,
        app.app_id,
        agent_color,
        browser,
        journal,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn apply_manifest_and_wait(
    pentagon: &dyn ProvisioningApi,
    access: &SecretString,
    slack: &dyn SlackProvisioningApi,
    slack_access: &SecretString,
    session: ProvisioningSession,
    agent_id: Uuid,
    app_id: String,
    agent_color: &str,
    browser: &dyn Browser,
    journal: &mut Journal,
) -> Result<ProvisionReceipt> {
    let desired = session
        .desired_manifest
        .as_ref()
        .ok_or_else(|| CliError::Remote("desired_manifest_missing".to_owned()))?;
    slack.validate(slack_access, Some(&app_id), desired).await?;
    slack
        .set_icon(slack_access, &app_id, agent_avatar_png(agent_color)?)
        .await?;
    println!("Preparing Pentagon's Slack event endpoint …");
    slack.wait_for_event_ingress(desired).await?;
    let update = match slack.update(slack_access, &app_id, desired).await {
        Ok(update) => update,
        Err(original) => {
            let exported = slack.export(slack_access, &app_id).await?;
            if managed_manifest_hash(&exported) != session.desired_manifest_hash {
                return Err(original);
            }
            crate::slack::ManifestUpdate {
                permissions_updated: false,
            }
        }
    };
    let exported = slack.export(slack_access, &app_id).await?;
    let observed = managed_manifest_hash(&exported);
    if observed != session.desired_manifest_hash {
        return Err(CliError::Remote("slack_manifest_mismatch".to_owned()));
    }
    let pending = pentagon
        .manifest_receipt(
            access,
            session.session_id,
            &observed,
            session.desired_manifest_version,
            update.permissions_updated,
        )
        .await?;
    let oauth_url = pending
        .oauth_url
        .ok_or_else(|| CliError::Remote("slack_oauth_url_missing".to_owned()))?;
    journal.record(JournalEntry {
        session_id: session.session_id,
        agent_id,
        app_id: Some(app_id.clone()),
        state: pending.state,
    })?;
    wait_for_activation(
        pentagon,
        access,
        &session,
        agent_id,
        app_id,
        Some(oauth_url.as_str()),
        browser,
        journal,
    )
    .await
}

fn agent_avatar_png(color: &str) -> Result<Vec<u8>> {
    if color == AVATAR_TEMPLATE_COLOR {
        return Ok(DEFAULT_AGENT_AVATAR_PNG.to_vec());
    }
    let color = parse_color(color)?;
    let decoder = png::Decoder::new(Cursor::new(DEFAULT_AGENT_AVATAR_PNG));
    let mut reader = decoder
        .read_info()
        .expect("embedded Pentagon avatar is a valid PNG");
    let mut pixels = vec![
        0;
        reader
            .output_buffer_size()
            .expect("avatar buffer size is bounded")
    ];
    let info = reader
        .next_frame(&mut pixels)
        .expect("embedded Pentagon avatar decodes");
    assert_eq!(info.color_type, png::ColorType::Rgba);
    pixels.truncate(info.buffer_size());
    for pixel in pixels.chunks_exact_mut(4) {
        if pixel == [0x35, 0x42, 0x5a, 0xff] {
            pixel[..3].copy_from_slice(&color);
        }
    }

    let mut encoded = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut encoded, info.width, info.height);
        encoder.set_color(png::ColorType::Rgba);
        encoder.set_depth(png::BitDepth::Eight);
        let mut writer = encoder
            .write_header()
            .expect("custom Pentagon avatar header encodes");
        writer
            .write_image_data(&pixels)
            .expect("custom Pentagon avatar pixels encode");
    }
    Ok(encoded)
}

fn parse_color(color: &str) -> Result<[u8; 3]> {
    if color.len() != 7 || !color.starts_with('#') {
        return Err(CliError::InvalidInput(
            "agent color must be a six-digit hexadecimal color",
        ));
    }
    let value = u32::from_str_radix(&color[1..], 16)
        .map_err(|_| CliError::InvalidInput("agent color must be a six-digit hexadecimal color"))?;
    Ok([(value >> 16) as u8, (value >> 8) as u8, value as u8])
}

#[allow(clippy::too_many_arguments)]
async fn wait_for_activation(
    pentagon: &dyn ProvisioningApi,
    access: &SecretString,
    session: &ProvisioningSession,
    agent_id: Uuid,
    app_id: String,
    oauth_url: Option<&str>,
    browser: &dyn Browser,
    journal: &mut Journal,
) -> Result<ProvisionReceipt> {
    if let Some(oauth_url) = oauth_url {
        println!("Opening Slack's installation approval screen …");
        browser.open(oauth_url)?;
    }
    let deadline = Instant::now() + Duration::from_secs(15 * 60);
    loop {
        if Instant::now() >= deadline {
            return Ok(ProvisionReceipt {
                session_id: session.session_id,
                app_id,
                state: "oauth_pending".to_owned(),
            });
        }
        let status = pentagon.session(access, session.session_id).await?;
        match status.state.as_str() {
            "active" => {
                journal.record(JournalEntry {
                    session_id: session.session_id,
                    agent_id,
                    app_id: Some(app_id.clone()),
                    state: status.state.clone(),
                })?;
                return Ok(ProvisionReceipt {
                    session_id: session.session_id,
                    app_id,
                    state: status.state,
                });
            }
            "oauth_pending" | "awaiting_admin_approval" => {
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
            "failed" | "expired" | "cancelled" => {
                return Err(CliError::Remote(
                    status.safe_error_code.unwrap_or(status.state),
                ));
            }
            state => {
                return Err(CliError::Remote(format!(
                    "unexpected_session_state_{state}"
                )));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;
    use secrecy::SecretString;
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};
    use url::Url;
    use uuid::Uuid;

    use super::{AVATAR_TEMPLATE_COLOR, agent_avatar_png, provision_slack};
    use crate::{
        CliError, Result,
        api::{CreateSessionRequest, ProvisioningApi, ProvisioningSession, RegisterAppRequest},
        auth::Browser,
        journal::Journal,
        slack::{CreatedSlackApp, ManifestUpdate, SlackProvisioningApi, managed_manifest_hash},
    };

    fn session(state: &str, manifest: &Value) -> ProvisioningSession {
        ProvisioningSession {
            contract_version: 1,
            session_id: Uuid::from_u128(1),
            agent_id: Uuid::from_u128(2),
            state: state.to_owned(),
            state_version: 0,
            slack_app_id: (state != "requested").then(|| "A123".to_owned()),
            expected_slack_team_id: Some("T123".to_owned()),
            registration_nonce: Some(SecretString::from("n".repeat(43))),
            bootstrap_manifest: Some(json!({ "display_information": { "name": "Test" } })),
            desired_manifest: Some(manifest.clone()),
            desired_manifest_version: 1,
            desired_manifest_hash: managed_manifest_hash(manifest),
            observed_manifest_hash: None,
            oauth_url: (state == "oauth_pending")
                .then(|| Url::parse("https://slack.com/oauth/v2/authorize?test=1").unwrap()),
            expires_at: "2026-08-30T23:00:00Z".to_owned(),
            safe_error_code: None,
        }
    }

    struct PentagonFake {
        manifest: Value,
        state: Mutex<String>,
    }
    #[async_trait]
    impl ProvisioningApi for PentagonFake {
        async fn create_session(
            &self,
            _: &SecretString,
            _: &CreateSessionRequest<'_>,
        ) -> Result<ProvisioningSession> {
            Ok(session("requested", &self.manifest))
        }
        async fn mark_create_unknown(
            &self,
            _: &SecretString,
            _: Uuid,
        ) -> Result<ProvisioningSession> {
            Ok(session("create_outcome_unknown", &self.manifest))
        }
        async fn register_app(
            &self,
            _: &SecretString,
            _: &RegisterAppRequest<'_>,
        ) -> Result<ProvisioningSession> {
            *self.state.lock().unwrap() = "app_registered".to_owned();
            Ok(session("app_registered", &self.manifest))
        }
        async fn manifest_receipt(
            &self,
            _: &SecretString,
            _: Uuid,
            hash: &str,
            _: u32,
            _: bool,
        ) -> Result<ProvisioningSession> {
            assert_eq!(hash, managed_manifest_hash(&self.manifest));
            *self.state.lock().unwrap() = "oauth_pending".to_owned();
            Ok(session("oauth_pending", &self.manifest))
        }
        async fn session(&self, _: &SecretString, _: Uuid) -> Result<ProvisioningSession> {
            let state = self.state.lock().unwrap().clone();
            Ok(session(
                if state == "oauth_pending" {
                    "active"
                } else {
                    &state
                },
                &self.manifest,
            ))
        }
        async fn session_for_agent(
            &self,
            access: &SecretString,
            _: Uuid,
        ) -> Result<ProvisioningSession> {
            self.session(access, Uuid::nil()).await
        }
    }

    struct SlackFake {
        manifest: Value,
        creates: Mutex<u32>,
        icon_uploads: Mutex<u32>,
        ingress_checks: Mutex<u32>,
        ingress_available: bool,
    }
    #[async_trait]
    impl SlackProvisioningApi for SlackFake {
        async fn validate(&self, _: &SecretString, _: Option<&str>, _: &Value) -> Result<()> {
            Ok(())
        }
        async fn create(&self, _: &SecretString, _: &Value) -> Result<CreatedSlackApp> {
            *self.creates.lock().unwrap() += 1;
            Ok(CreatedSlackApp {
                app_id: "A123".to_owned(),
                client_id: "123.456".to_owned(),
                client_secret: SecretString::from("client-secret-value"),
                signing_secret: SecretString::from("signing-secret-value"),
            })
        }
        async fn update(&self, _: &SecretString, _: &str, _: &Value) -> Result<ManifestUpdate> {
            Ok(ManifestUpdate {
                permissions_updated: false,
            })
        }
        async fn export(&self, _: &SecretString, _: &str) -> Result<Value> {
            Ok(self.manifest.clone())
        }
        async fn set_icon(&self, _: &SecretString, _: &str, png: Vec<u8>) -> Result<()> {
            assert!(png.starts_with(b"\x89PNG\r\n\x1a\n"));
            *self.icon_uploads.lock().unwrap() += 1;
            Ok(())
        }
        async fn wait_for_event_ingress(&self, _: &Value) -> Result<()> {
            *self.ingress_checks.lock().unwrap() += 1;
            if self.ingress_available {
                Ok(())
            } else {
                Err(CliError::Remote(
                    "slack_event_request_url_unavailable".to_owned(),
                ))
            }
        }
    }

    #[derive(Default)]
    struct BrowserFake(Mutex<Vec<String>>);
    impl Browser for BrowserFake {
        fn open(&self, url: &str) -> Result<()> {
            self.0.lock().unwrap().push(url.to_owned());
            Ok(())
        }
    }

    fn manifest() -> Value {
        json!({
            "features": { "app_home": { "messages_tab_enabled": true, "messages_tab_read_only_enabled": false }, "agent_view": {} },
            "oauth_config": { "redirect_urls": ["https://example.test/callback"], "scopes": { "bot": ["chat:write"], "user": [] } },
            "settings": { "interactivity": { "is_enabled": true, "request_url": "https://example.test/actions" }, "event_subscriptions": { "request_url": "https://example.test/events", "bot_events": ["app_mention"] } }
        })
    }

    #[test]
    fn default_agent_avatar_matches_app_rendered_fixture() {
        let encoded = agent_avatar_png(AVATAR_TEMPLATE_COLOR).unwrap();
        let decoder = png::Decoder::new(std::io::Cursor::new(&encoded));
        let mut reader = decoder.read_info().unwrap();
        let mut decoded = vec![0; reader.output_buffer_size().unwrap()];
        let info = reader.next_frame(&mut decoded).unwrap();

        assert_eq!(AVATAR_TEMPLATE_COLOR, "#35425a");
        assert_eq!((info.width, info.height), (512, 512));
        assert_eq!(
            format!("{:x}", Sha256::digest(&encoded)),
            "9749b153a22752fc862c0ff707d82ea7e045ef08129bb70ddc3bf22f1b2741ba"
        );
    }

    #[test]
    fn configured_color_preserves_the_standard_robot_avatar() {
        let encoded = agent_avatar_png("#123abc").unwrap();
        let decoder = png::Decoder::new(std::io::Cursor::new(&encoded));
        let mut reader = decoder.read_info().unwrap();
        let mut decoded = vec![0; reader.output_buffer_size().unwrap()];
        let info = reader.next_frame(&mut decoded).unwrap();
        decoded.truncate(info.buffer_size());

        assert_eq!(&decoded[0..4], &[0x12, 0x3a, 0xbc, 0xff]);
        assert!(
            decoded
                .chunks_exact(4)
                .any(|pixel| pixel != [0x12, 0x3a, 0xbc, 0xff])
        );
    }

    #[tokio::test]
    async fn provisions_once_and_journals_only_resumable_coordinates() {
        let manifest = manifest();
        let pentagon = PentagonFake {
            manifest: manifest.clone(),
            state: Mutex::new("requested".to_owned()),
        };
        let slack = SlackFake {
            manifest,
            creates: Mutex::new(0),
            icon_uploads: Mutex::new(0),
            ingress_checks: Mutex::new(0),
            ingress_available: true,
        };
        let browser = BrowserFake::default();
        let directory = tempfile::tempdir().unwrap();
        let mut journal = Journal::at(directory.path().join("journal.json")).unwrap();
        let receipt = provision_slack(
            &pentagon,
            &SecretString::from(format!("pga_{}", "a".repeat(43))),
            &slack,
            &SecretString::from("xoxe.xoxp-test"),
            Uuid::from_u128(2),
            AVATAR_TEMPLATE_COLOR,
            "T123",
            &browser,
            &mut journal,
        )
        .await
        .unwrap();
        assert_eq!(receipt.state, "active");
        assert_eq!(*slack.creates.lock().unwrap(), 1);
        assert_eq!(*slack.icon_uploads.lock().unwrap(), 1);
        assert_eq!(*slack.ingress_checks.lock().unwrap(), 1);
        assert_eq!(
            browser.0.lock().unwrap().as_slice(),
            ["https://slack.com/oauth/v2/authorize?test=1"]
        );
        let raw = std::fs::read_to_string(directory.path().join("journal.json")).unwrap();
        assert!(!raw.contains("xoxe"));
        assert!(!raw.contains("pga_"));
        assert!(!raw.contains("client-secret"));
    }

    #[tokio::test]
    async fn unavailable_event_ingress_stops_before_slack_approval() {
        let manifest = manifest();
        let pentagon = PentagonFake {
            manifest: manifest.clone(),
            state: Mutex::new("requested".to_owned()),
        };
        let slack = SlackFake {
            manifest,
            creates: Mutex::new(0),
            icon_uploads: Mutex::new(0),
            ingress_checks: Mutex::new(0),
            ingress_available: false,
        };
        let browser = BrowserFake::default();
        let directory = tempfile::tempdir().unwrap();
        let mut journal = Journal::at(directory.path().join("journal.json")).unwrap();

        let error = provision_slack(
            &pentagon,
            &SecretString::from("pga-test"),
            &slack,
            &SecretString::from("xoxe.xoxp-test"),
            Uuid::from_u128(2),
            AVATAR_TEMPLATE_COLOR,
            "T123",
            &browser,
            &mut journal,
        )
        .await
        .unwrap_err();

        assert!(
            matches!(error, CliError::Remote(ref code) if code == "slack_event_request_url_unavailable")
        );
        assert_eq!(*slack.creates.lock().unwrap(), 1);
        assert_eq!(*slack.ingress_checks.lock().unwrap(), 1);
        assert!(browser.0.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn wrong_workspace_stops_before_slack_app_creation() {
        let manifest = manifest();
        let pentagon = PentagonFake {
            manifest: manifest.clone(),
            state: Mutex::new("requested".to_owned()),
        };
        let slack = SlackFake {
            manifest,
            creates: Mutex::new(0),
            icon_uploads: Mutex::new(0),
            ingress_checks: Mutex::new(0),
            ingress_available: true,
        };
        let browser = BrowserFake::default();
        let directory = tempfile::tempdir().unwrap();
        let mut journal = Journal::at(directory.path().join("journal.json")).unwrap();
        let error = provision_slack(
            &pentagon,
            &SecretString::from("pga-test"),
            &slack,
            &SecretString::from("xoxe.xoxp-test"),
            Uuid::from_u128(2),
            AVATAR_TEMPLATE_COLOR,
            "TWRONG",
            &browser,
            &mut journal,
        )
        .await
        .unwrap_err();
        assert!(matches!(error, CliError::WrongSlackWorkspace));
        assert_eq!(*slack.creates.lock().unwrap(), 0);
    }

    #[tokio::test]
    async fn reconnecting_an_active_agent_repairs_its_icon() {
        let manifest = manifest();
        let pentagon = PentagonFake {
            manifest: manifest.clone(),
            state: Mutex::new("active".to_owned()),
        };
        let slack = SlackFake {
            manifest,
            creates: Mutex::new(0),
            icon_uploads: Mutex::new(0),
            ingress_checks: Mutex::new(0),
            ingress_available: true,
        };
        let browser = BrowserFake::default();
        let directory = tempfile::tempdir().unwrap();
        let agent_id = Uuid::from_u128(2);
        let mut journal = Journal::at(directory.path().join("journal.json")).unwrap();
        journal
            .record(crate::journal::JournalEntry {
                session_id: Uuid::from_u128(1),
                agent_id,
                app_id: Some("A123".to_owned()),
                state: "active".to_owned(),
            })
            .unwrap();

        let receipt = provision_slack(
            &pentagon,
            &SecretString::from("pga-test"),
            &slack,
            &SecretString::from("xoxe.xoxp-test"),
            agent_id,
            AVATAR_TEMPLATE_COLOR,
            "T123",
            &browser,
            &mut journal,
        )
        .await
        .unwrap();

        assert_eq!(receipt.state, "active");
        assert_eq!(*slack.creates.lock().unwrap(), 0);
        assert_eq!(*slack.icon_uploads.lock().unwrap(), 1);
    }

    #[tokio::test]
    async fn interrupted_registration_never_creates_a_second_slack_app() {
        let manifest = manifest();
        let pentagon = PentagonFake {
            manifest: manifest.clone(),
            state: Mutex::new("requested".to_owned()),
        };
        let slack = SlackFake {
            manifest,
            creates: Mutex::new(0),
            icon_uploads: Mutex::new(0),
            ingress_checks: Mutex::new(0),
            ingress_available: true,
        };
        let browser = BrowserFake::default();
        let directory = tempfile::tempdir().unwrap();
        let agent_id = Uuid::from_u128(2);
        let mut journal = Journal::at(directory.path().join("journal.json")).unwrap();
        journal
            .record(crate::journal::JournalEntry {
                session_id: Uuid::from_u128(1),
                agent_id,
                app_id: Some("A123".to_owned()),
                state: "app_created".to_owned(),
            })
            .unwrap();

        let error = provision_slack(
            &pentagon,
            &SecretString::from("pga-test"),
            &slack,
            &SecretString::from("xoxe.xoxp-test"),
            agent_id,
            AVATAR_TEMPLATE_COLOR,
            "T123",
            &browser,
            &mut journal,
        )
        .await
        .unwrap_err();

        assert!(matches!(
            error,
            CliError::Remote(ref code) if code == "unregistered_slack_app_requires_exact_cleanup"
        ));
        assert_eq!(*slack.creates.lock().unwrap(), 0);
    }
}
