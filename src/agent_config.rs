use std::path::{Path, PathBuf};

use rand::prelude::IndexedRandom;
use serde::Deserialize;

use crate::{CliError, Result};

const AGENT_COLORS: &[&str] = &[
    "#6366f1", "#8b5cf6", "#a855f7", "#d946ef", "#ec4899", "#f43f5e", "#ef4444", "#f97316",
    "#f59e0b", "#84cc16", "#22c55e", "#06b6d4",
];
const MAX_CONFIG_BYTES: u64 = 262_144;
const MAX_INSTRUCTION_CHARACTERS: usize = 65_536;

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentConfigFile {
    name: Option<String>,
    model: Option<String>,
    color: Option<String>,
    instructions: Option<String>,
    slack: Option<bool>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct AgentCreateConfig {
    pub name: String,
    pub model: Option<String>,
    pub color: Option<String>,
    pub instructions: Option<String>,
    pub slack: bool,
}

pub struct AgentCreateInput {
    pub config: Option<PathBuf>,
    pub name: Option<String>,
    pub model: Option<String>,
    pub color: Option<String>,
    pub instructions: Option<PathBuf>,
    pub slack: bool,
}

pub fn load_agent_create_config(input: AgentCreateInput) -> Result<AgentCreateConfig> {
    let file = input
        .config
        .as_deref()
        .map(read_config)
        .transpose()?
        .unwrap_or_default();
    let name = input.name.or(file.name).unwrap_or_default();
    let name = name.trim().to_owned();
    if name.is_empty() || name.chars().count() > 200 {
        return Err(CliError::InvalidInput(
            "agent name must contain between 1 and 200 characters",
        ));
    }

    let model = input
        .model
        .or(file.model)
        .map(|value| value.trim().to_owned());
    if model.as_deref().is_some_and(|value| {
        value.is_empty()
            || value.len() > 160
            || !value.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'_' | b'-' | b'/')
            })
    }) {
        return Err(CliError::InvalidInput(
            "model must be a valid Pentagon catalog identifier",
        ));
    }

    let color = input
        .color
        .or(file.color)
        .map(|value| value.trim().to_ascii_lowercase())
        .or_else(|| Some(random_agent_color()));
    if color.as_deref().is_some_and(|value| !valid_color(value)) {
        return Err(CliError::InvalidInput(
            "agent color must be a six-digit hexadecimal color such as #35425a",
        ));
    }

    let instructions = if let Some(path) = input.instructions {
        Some(
            std::fs::read_to_string(path)
                .map_err(|_| CliError::InvalidInput("unable to read instructions file"))?,
        )
    } else {
        file.instructions
    };
    if instructions
        .as_deref()
        .is_some_and(|value| value.chars().count() > MAX_INSTRUCTION_CHARACTERS)
    {
        return Err(CliError::InvalidInput(
            "agent instructions exceed 65,536 characters",
        ));
    }

    Ok(AgentCreateConfig {
        name,
        model,
        color,
        instructions,
        slack: input.slack || file.slack.unwrap_or(false),
    })
}

fn random_agent_color() -> String {
    AGENT_COLORS
        .choose(&mut rand::rng())
        .expect("Pentagon agent palette is not empty")
        .to_string()
}

fn read_config(path: &Path) -> Result<AgentConfigFile> {
    let metadata = std::fs::metadata(path)
        .map_err(|_| CliError::InvalidInput("unable to read agent configuration file"))?;
    if metadata.len() > MAX_CONFIG_BYTES {
        return Err(CliError::InvalidInput(
            "agent configuration file exceeds 256 KiB",
        ));
    }
    let source = std::fs::read_to_string(path)
        .map_err(|_| CliError::InvalidInput("unable to read agent configuration file"))?;
    serde_yaml_ng::from_str(&source)
        .map_err(|_| CliError::InvalidInput("agent configuration is not valid YAML"))
}

fn valid_color(value: &str) -> bool {
    value.len() == 7
        && value.starts_with('#')
        && value[1..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::{AGENT_COLORS, AgentCreateInput, load_agent_create_config};

    #[test]
    fn yaml_and_flags_resolve_to_one_configuration() {
        let directory = tempfile::tempdir().unwrap();
        let config_path = directory.path().join("agent.yaml");
        std::fs::write(
            &config_path,
            "name: Treasury\nmodel: openai/gpt-5.6-terra\ncolor: '#123ABC'\ninstructions: |\n  Keep reconciliations current.\nslack: true\n",
        )
        .unwrap();

        let config = load_agent_create_config(AgentCreateInput {
            config: Some(config_path),
            name: None,
            model: None,
            color: None,
            instructions: None,
            slack: false,
        })
        .unwrap();

        assert_eq!(config.name, "Treasury");
        assert_eq!(config.model.as_deref(), Some("openai/gpt-5.6-terra"));
        assert_eq!(config.color.as_deref(), Some("#123abc"));
        assert_eq!(
            config.instructions.as_deref(),
            Some("Keep reconciliations current.\n")
        );
        assert!(config.slack);
    }

    #[test]
    fn explicit_flags_override_yaml_without_changing_unspecified_values() {
        let directory = tempfile::tempdir().unwrap();
        let config_path = directory.path().join("agent.yaml");
        std::fs::write(
            &config_path,
            "name: From YAML\nmodel: openai/gpt-5.6-luna\ncolor: '#111111'\n",
        )
        .unwrap();

        let config = load_agent_create_config(AgentCreateInput {
            config: Some(config_path),
            name: Some("From flag".to_owned()),
            model: None,
            color: Some("#ABCDEF".to_owned()),
            instructions: None,
            slack: true,
        })
        .unwrap();

        assert_eq!(config.name, "From flag");
        assert_eq!(config.model.as_deref(), Some("openai/gpt-5.6-luna"));
        assert_eq!(config.color.as_deref(), Some("#abcdef"));
        assert!(config.slack);
    }

    #[test]
    fn rejects_unknown_fields_including_configurable_emoji() {
        let directory = tempfile::tempdir().unwrap();
        let config_path = directory.path().join("agent.yaml");
        std::fs::write(&config_path, "name: Treasury\nemoji: 🧭\n").unwrap();

        let error = load_agent_create_config(AgentCreateInput {
            config: Some(config_path),
            name: None,
            model: None,
            color: None,
            instructions: None,
            slack: false,
        })
        .unwrap_err();

        assert!(error.to_string().contains("not valid YAML"));
    }

    #[test]
    fn defers_supported_model_membership_to_pentagons_catalog() {
        let config = load_agent_create_config(AgentCreateInput {
            config: None,
            name: Some("Treasury".to_owned()),
            model: Some("openai/future-model-9".to_owned()),
            color: None,
            instructions: None,
            slack: false,
        })
        .unwrap();
        assert_eq!(config.model.as_deref(), Some("openai/future-model-9"));
        assert!(AGENT_COLORS.contains(&config.color.as_deref().unwrap()));
    }

    #[test]
    fn rejects_malformed_model_identifiers_and_colors() {
        for (model, color) in [
            (Some("Not a model".to_owned()), None),
            (None, Some("blue".to_owned())),
        ] {
            assert!(
                load_agent_create_config(AgentCreateInput {
                    config: None,
                    name: Some("Treasury".to_owned()),
                    model,
                    color,
                    instructions: None,
                    slack: false,
                })
                .is_err()
            );
        }
    }
}
