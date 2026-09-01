use thiserror::Error;

pub type Result<T> = std::result::Result<T, CliError>;

#[derive(Debug, Error)]
pub enum CliError {
    #[error("invalid input: {0}")]
    InvalidInput(&'static str),

    #[error("local credential access failed")]
    CredentialStore,

    #[error("Pentagon authorization is required; run `pentagon auth login --org <org>`")]
    PentagonAuthorizationRequired,

    #[error("Slack authorization is required; run `pentagon slack auth login`")]
    SlackAuthorizationRequired,

    #[error("the Slack credential belongs to a different workspace")]
    WrongSlackWorkspace,

    #[error(
        "the operation stopped because Slack app creation may have succeeded; inspect the app dashboard before retrying"
    )]
    CreateOutcomeUnknown,

    #[error("remote operation failed: {0}")]
    Remote(String),

    #[error("device authorization expired before it was approved")]
    DeviceAuthorizationExpired,

    #[error("device authorization was denied")]
    DeviceAuthorizationDenied,
}

impl CliError {
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::InvalidInput(_) => 2,
            Self::PentagonAuthorizationRequired | Self::SlackAuthorizationRequired => 3,
            Self::WrongSlackWorkspace => 4,
            Self::CreateOutcomeUnknown => 5,
            Self::CredentialStore
            | Self::Remote(_)
            | Self::DeviceAuthorizationExpired
            | Self::DeviceAuthorizationDenied => 1,
        }
    }
}
