use secrecy::{ExposeSecret, SecretString};

const REDACTED: &str = "[redacted]";

#[derive(Default)]
pub struct Redactor {
    secrets: Vec<SecretString>,
}

impl Redactor {
    pub fn register(&mut self, secret: SecretString) {
        if !secret.expose_secret().is_empty() {
            self.secrets.push(secret);
        }
    }

    pub fn redact(&self, value: &str) -> String {
        let mut redacted = value.to_owned();
        for secret in &self.secrets {
            let raw = secret.expose_secret();
            redacted = redacted.replace(raw, REDACTED);
            redacted = redacted.replace(&urlencode(raw), REDACTED);
            redacted = redacted.replace(&json_escape(raw), REDACTED);
        }
        redact_token_shapes(redacted)
    }
}

fn urlencode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

fn json_escape(value: &str) -> String {
    serde_json::to_string(value)
        .unwrap_or_default()
        .trim_matches('"')
        .to_owned()
}

fn redact_token_shapes(value: String) -> String {
    const PREFIXES: [&str; 8] = [
        "xoxe.xoxp-",
        "xoxe.xoxb-",
        "xoxe-",
        "xoxb-",
        "xoxp-",
        "xapp-",
        "pgr_",
        "pga_",
    ];
    let mut redacted = value;
    for prefix in PREFIXES {
        while let Some(start) = redacted.find(prefix) {
            let suffix = &redacted[start..];
            let end = suffix
                .char_indices()
                .take_while(|(_, character)| {
                    character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-')
                })
                .map(|(offset, character)| offset + character.len_utf8())
                .last()
                .unwrap_or(0);
            redacted.replace_range(start..start + end, REDACTED);
        }
    }
    redacted
}

#[cfg(test)]
mod tests {
    use secrecy::SecretString;

    use super::Redactor;

    const SENTINEL: &str = "xoxe-1-fake-secret-sentinel";

    #[test]
    fn redacts_registered_raw_encoded_json_and_wrapped_forms() {
        let mut redactor = Redactor::default();
        redactor.register(SecretString::from(SENTINEL));

        for value in [
            SENTINEL.to_owned(),
            format!("Bearer {SENTINEL}"),
            "token=xoxe-1-fake-secret-sentinel".to_owned(),
            format!("\"{SENTINEL}\""),
            format!("upstream error ({SENTINEL})"),
        ] {
            let output = redactor.redact(&value);
            assert!(!output.contains(SENTINEL), "leaked from {value:?}");
        }
    }

    #[test]
    fn redacts_unregistered_known_token_shapes() {
        for value in [
            "Slack rejected xoxb-fake-token-sentinel-value",
            r#"{\"token\":\"xoxe.xoxp-fake-configuration-access-token\"}"#,
            "refresh=xoxe-1-fake-refresh-token-value&next=safe",
            "Bearer pga_fake-pentagon-access-token-value",
            "wrapped=(xapp-fake-app-level-token-value)",
        ] {
            let output = Redactor::default().redact(value);
            assert!(!output.contains("fake-"), "leaked from {value:?}");
            assert!(output.contains("[redacted]"), "did not redact {value:?}");
        }
    }

    #[test]
    fn preserves_safe_diagnostics() {
        let output = Redactor::default().redact("wrong_slack_workspace: expected T123");
        assert_eq!(output, "wrong_slack_workspace: expected T123");
    }
}
