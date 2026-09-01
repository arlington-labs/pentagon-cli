use std::io::IsTerminal;

use clap::{Args, Parser, Subcommand};
use secrecy::{ExposeSecret, SecretString};

use crate::{
    CliError, Result,
    agent_config::{AgentCreateInput, load_agent_create_config},
    api::{
        AgentApi, CreateAgentRequest, DeviceApi, DeviceRevocationApi, HttpPentagonApi,
        OrganizationEndpoint, ProvisioningApi, ProvisioningSession,
    },
    auth::{SystemBrowser, access_credential, login},
    credential_store::{CredentialLock, CredentialStore, OsCredentialStore},
    journal::Journal,
    provision::provision_slack,
    slack::SlackClient,
};

const SLACK_CONFIGURATION_TOKENS_URL: &str = "https://api.slack.com/apps";
const ACTIVE_ORGANIZATION_ACCOUNT: &str = "active-organization";

async fn active_endpoint() -> Result<OrganizationEndpoint> {
    let organization = OsCredentialStore
        .get(ACTIVE_ORGANIZATION_ACCOUNT)
        .await?
        .ok_or(CliError::PentagonAuthorizationRequired)?;
    OrganizationEndpoint::resolve(organization.expose_secret())
}

async fn set_active_organization(slug: &str) -> Result<()> {
    OsCredentialStore
        .set(
            ACTIVE_ORGANIZATION_ACCOUNT,
            &SecretString::from(slug.to_owned()),
        )
        .await
}

fn slack_auth_setup_instructions() -> String {
    format!(
        "Generate a token at {SLACK_CONFIGURATION_TOKENS_URL}\nUnder “Your App Configuration Tokens,” choose “Generate Token,” then paste the refresh token (xoxe-…)."
    )
}

fn slack_auth_success(team_id: &str, color: bool) -> String {
    let heading = if color {
        "\u{1b}[32m✓ Slack access ready\u{1b}[0m"
    } else {
        "✓ Slack access ready"
    };

    format!("{heading}\n  Workspace {team_id} · credential saved to Keychain")
}

#[derive(Debug, Parser)]
#[command(name = "pentagon", version, about = "The Pentagon infrastructure CLI")]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Authenticate this device with Pentagon.
    Auth(AuthArgs),
    /// Create and inspect Pentagon agents.
    Agent(AgentArgs),
    /// Connect a Pentagon agent to Slack.
    Slack(SlackArgs),
}

#[derive(Debug, Args)]
struct AuthArgs {
    #[command(subcommand)]
    command: AuthCommand,
}

#[derive(Debug, Subcommand)]
enum AuthCommand {
    /// Approve this device in a browser.
    Login {
        /// Pentagon organization slug.
        #[arg(long)]
        org: String,
    },
    /// Show the current device authorization without printing credentials.
    Status,
    /// Revoke this device and remove its local credential.
    Logout,
}

#[derive(Debug, Args)]
struct AgentArgs {
    #[command(subcommand)]
    command: AgentCommand,
}

#[derive(Debug, Subcommand)]
enum AgentCommand {
    /// Create an agent, optionally provisioning its Slack app.
    Create {
        #[arg(
            long,
            value_name = "FILE",
            help = "Read agent configuration from YAML FILE"
        )]
        config: Option<std::path::PathBuf>,
        #[arg(long, help = "Agent name (overrides YAML)")]
        name: Option<String>,
        #[arg(
            long,
            help = "Certified model ID; Pentagon selects a concrete model when omitted (overrides YAML)"
        )]
        model: Option<String>,
        #[arg(
            long,
            help = "Agent background color, such as #35425a (overrides YAML)"
        )]
        color: Option<String>,
        #[arg(long, value_name = "FILE", help = "Read agent instructions from FILE")]
        instructions: Option<std::path::PathBuf>,
        #[arg(long, help = "Create and connect the agent's Slack app")]
        slack: bool,
    },
    /// List agents available to the current administrator.
    List,
}

#[derive(Debug, Args)]
struct SlackArgs {
    #[command(subcommand)]
    command: SlackCommand,
}

#[derive(Debug, Subcommand)]
enum SlackCommand {
    /// Manage the local Slack app-configuration credential.
    Auth(SlackAuthArgs),
    /// Create a dedicated Slack app for an agent.
    Create {
        #[arg(long)]
        agent: String,
    },
    /// Show resumable provisioning status.
    Status {
        #[arg(long)]
        agent: String,
    },
}

#[derive(Debug, Args)]
struct SlackAuthArgs {
    #[command(subcommand)]
    command: SlackAuthCommand,
}

#[derive(Debug, Subcommand)]
enum SlackAuthCommand {
    Login,
    Status,
    Logout,
}

impl Cli {
    pub async fn run(self) -> Result<()> {
        match self.command {
            Command::Auth(AuthArgs {
                command: AuthCommand::Login { org },
            }) if org.trim().is_empty() => {
                Err(CliError::InvalidInput("organization must not be empty"))
            }
            Command::Auth(AuthArgs {
                command: AuthCommand::Login { org },
            }) => {
                let endpoint = OrganizationEndpoint::resolve(&org)?;
                let api = HttpPentagonApi::new(endpoint.clone())?;
                let device_name = std::env::var("HOSTNAME")
                    .ok()
                    .filter(|name| !name.trim().is_empty())
                    .unwrap_or_else(|| "Pentagon CLI device".to_owned());
                let receipt = login(
                    &endpoint,
                    &api,
                    &OsCredentialStore,
                    &SystemBrowser,
                    &device_name,
                )
                .await?;
                set_active_organization(&endpoint.slug).await?;
                println!("Organization: {}", endpoint.slug);
                println!("Device: {}", receipt.device_id);
                println!("Permissions: {}", receipt.scopes.join(", "));
                println!("Credential saved in your operating-system keychain.");
                Ok(())
            }
            Command::Auth(AuthArgs {
                command: AuthCommand::Status,
            }) => {
                let endpoint = active_endpoint().await?;
                let api = HttpPentagonApi::new(endpoint.clone())?;
                access_credential(&endpoint, &api, &OsCredentialStore).await?;
                println!("Authenticated to Pentagon organization {}.", endpoint.slug);
                Ok(())
            }
            Command::Auth(AuthArgs {
                command: AuthCommand::Logout,
            }) => {
                let endpoint = active_endpoint().await?;
                let api = HttpPentagonApi::new(endpoint.clone())?;
                let _lock = CredentialLock::acquire(&endpoint.keychain_account())?;
                let Some(refresh) = OsCredentialStore.get(&endpoint.keychain_account()).await?
                else {
                    OsCredentialStore
                        .delete(ACTIVE_ORGANIZATION_ACCOUNT)
                        .await?;
                    println!("This device has no local Pentagon credential.");
                    return Ok(());
                };
                let issued = api.refresh(&refresh).await?;
                OsCredentialStore
                    .set(&endpoint.keychain_account(), &issued.refresh_token)
                    .await?;
                api.revoke_device(&issued.access_token, issued.device_id)
                    .await?;
                OsCredentialStore
                    .delete(&endpoint.keychain_account())
                    .await?;
                OsCredentialStore
                    .delete(ACTIVE_ORGANIZATION_ACCOUNT)
                    .await?;
                println!("This Pentagon device was revoked and its local credential removed.");
                Ok(())
            }
            Command::Agent(AgentArgs {
                command: AgentCommand::List,
            }) => {
                let endpoint = active_endpoint().await?;
                let pentagon = HttpPentagonApi::new(endpoint.clone())?;
                let access = access_credential(&endpoint, &pentagon, &OsCredentialStore).await?;
                for agent in pentagon.list_agents(&access).await? {
                    println!(
                        "{}\t{}\t{}",
                        agent.agent_id, agent.name, agent.execution_mode
                    );
                }
                Ok(())
            }
            Command::Agent(AgentArgs {
                command:
                    AgentCommand::Create {
                        config,
                        name,
                        model,
                        color,
                        instructions,
                        slack,
                    },
            }) => {
                let config = load_agent_create_config(AgentCreateInput {
                    config,
                    name,
                    model,
                    color,
                    instructions,
                    slack,
                })?;
                let endpoint = active_endpoint().await?;
                let pentagon = HttpPentagonApi::new(endpoint.clone())?;
                let access = access_credential(&endpoint, &pentagon, &OsCredentialStore).await?;
                let agent = pentagon
                    .create_agent(
                        &access,
                        &CreateAgentRequest {
                            name: &config.name,
                            model: config.model.as_deref(),
                            color: config.color.as_deref(),
                            instructions: config.instructions.as_deref(),
                        },
                    )
                    .await?;
                println!("Agent created: {} ({})", agent.name, agent.agent_id);
                println!("Model: {}", agent.model);
                println!("Appearance: 🤖 on {}", agent.color);
                if config.slack {
                    provision_agent_slack(&agent).await?;
                }
                Ok(())
            }
            Command::Slack(SlackArgs {
                command:
                    SlackCommand::Auth(SlackAuthArgs {
                        command: SlackAuthCommand::Login,
                    }),
            }) => {
                let endpoint = active_endpoint().await?;
                println!("{}", slack_auth_setup_instructions());
                let refresh = rpassword::prompt_password(
                    "Slack app-configuration refresh token (input hidden): ",
                )
                .map_err(|_| CliError::InvalidInput("unable to read hidden input"))?;
                if !refresh.starts_with("xoxe-") || refresh.len() > 2048 {
                    return Err(CliError::InvalidInput(
                        "expected a Slack app-configuration refresh token",
                    ));
                }
                let slack = SlackClient::new()?;
                let _lock = CredentialLock::acquire(&endpoint.slack_keychain_account())?;
                let rotated = slack.rotate(&secrecy::SecretString::from(refresh)).await?;
                OsCredentialStore
                    .set(&endpoint.slack_keychain_account(), &rotated.refresh)
                    .await?;
                println!(
                    "{}",
                    slack_auth_success(
                        &rotated.team_id,
                        std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none(),
                    )
                );
                Ok(())
            }
            Command::Slack(SlackArgs {
                command:
                    SlackCommand::Auth(SlackAuthArgs {
                        command: SlackAuthCommand::Status,
                    }),
            }) => {
                let endpoint = active_endpoint().await?;
                if OsCredentialStore
                    .get(&endpoint.slack_keychain_account())
                    .await?
                    .is_some()
                {
                    println!("A Slack app-configuration refresh credential is stored locally.");
                } else {
                    println!("Slack app-configuration authorization is not configured.");
                }
                Ok(())
            }
            Command::Slack(SlackArgs {
                command:
                    SlackCommand::Auth(SlackAuthArgs {
                        command: SlackAuthCommand::Logout,
                    }),
            }) => {
                let endpoint = active_endpoint().await?;
                OsCredentialStore
                    .delete(&endpoint.slack_keychain_account())
                    .await?;
                println!("Local Slack app-configuration credential removed.");
                Ok(())
            }
            Command::Slack(SlackArgs {
                command: SlackCommand::Create { agent },
            }) => {
                let agent = resolve_agent(&agent).await?;
                provision_agent_slack(&agent).await
            }
            Command::Slack(SlackArgs {
                command: SlackCommand::Status { agent },
            }) => {
                let agent_id = resolve_agent(&agent).await?.agent_id;
                let endpoint = active_endpoint().await?;
                let pentagon = HttpPentagonApi::new(endpoint.clone())?;
                let access = access_credential(&endpoint, &pentagon, &OsCredentialStore).await?;
                let mut journal = Journal::open()?;
                let status =
                    discover_agent_slack(&pentagon, &access, agent_id, &mut journal).await?;
                println!("Agent: {}", status.agent_id);
                println!("Session: {}", status.session_id);
                println!("State: {}", status.state);
                if let Some(app_id) = status.slack_app_id {
                    println!("Slack app: {app_id}");
                }
                if let Some(code) = status.safe_error_code {
                    println!("Recovery code: {code}");
                }
                Ok(())
            }
        }
    }
}

struct LockedSlackCredential {
    _lock: CredentialLock,
    credential: crate::slack::SlackConfigurationCredential,
}

async fn lock_and_rotate_slack_credential(
    endpoint: &OrganizationEndpoint,
    slack: &SlackClient,
) -> Result<LockedSlackCredential> {
    let account = endpoint.slack_keychain_account();
    let lock = CredentialLock::acquire(&account)?;
    let refresh = OsCredentialStore
        .get(&account)
        .await?
        .ok_or(CliError::SlackAuthorizationRequired)?;
    let credential = slack.rotate(&refresh).await?;
    OsCredentialStore.set(&account, &credential.refresh).await?;
    Ok(LockedSlackCredential {
        _lock: lock,
        credential,
    })
}

async fn resolve_agent(value: &str) -> Result<crate::api::AgentSummary> {
    let requested_id = value.parse::<uuid::Uuid>().ok();
    let endpoint = active_endpoint().await?;
    let pentagon = HttpPentagonApi::new(endpoint.clone())?;
    let access = access_credential(&endpoint, &pentagon, &OsCredentialStore).await?;
    let matches = pentagon
        .list_agents(&access)
        .await?
        .into_iter()
        .filter(|agent| requested_id == Some(agent.agent_id) || agent.name == value)
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [agent] => Ok(crate::api::AgentSummary {
            agent_id: agent.agent_id,
            name: agent.name.clone(),
            model: agent.model.clone(),
            color: agent.color.clone(),
            emoji: agent.emoji.clone(),
            execution_mode: agent.execution_mode.clone(),
        }),
        [] => Err(CliError::InvalidInput("agent name was not found")),
        _ => Err(CliError::InvalidInput(
            "agent name is ambiguous; use its UUID",
        )),
    }
}

async fn discover_agent_slack(
    pentagon: &dyn ProvisioningApi,
    access: &secrecy::SecretString,
    agent_id: uuid::Uuid,
    journal: &mut Journal,
) -> Result<ProvisioningSession> {
    let session = pentagon.session_for_agent(access, agent_id).await?;
    journal.record(crate::journal::JournalEntry {
        session_id: session.session_id,
        agent_id,
        app_id: session.slack_app_id.clone(),
        state: session.state.clone(),
    })?;
    Ok(session)
}

async fn provision_agent_slack(agent: &crate::api::AgentSummary) -> Result<()> {
    let endpoint = active_endpoint().await?;
    let pentagon = HttpPentagonApi::new(endpoint.clone())?;
    let access = access_credential(&endpoint, &pentagon, &OsCredentialStore).await?;
    let slack = SlackClient::new()?;
    // The guard lives through every Slack mutation and reconciliation read. Two
    // local CLI processes must not race one team's single-use credential.
    let locked_slack = lock_and_rotate_slack_credential(&endpoint, &slack).await?;
    let receipt = provision_slack(
        &pentagon,
        &access,
        &slack,
        &locked_slack.credential.access,
        agent.agent_id,
        &agent.color,
        &locked_slack.credential.team_id,
        &SystemBrowser,
        &mut Journal::open()?,
    )
    .await?;
    println!("Provisioning session: {}", receipt.session_id);
    println!("Slack app: {}", receipt.app_id);
    println!("State: {}", receipt.state);
    if receipt.state != "active" {
        println!("Slack approval is still pending; the Pentagon agent was preserved.");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::{AuthCommand, Cli, Command, slack_auth_setup_instructions, slack_auth_success};

    #[test]
    fn slack_auth_explains_where_to_generate_the_refresh_token() {
        let instructions = slack_auth_setup_instructions();
        assert!(instructions.contains("https://api.slack.com/apps"));
        assert!(instructions.contains("Your App Configuration Tokens"));
        assert!(instructions.contains("refresh token"));
    }

    #[test]
    fn slack_auth_success_is_clear_with_and_without_terminal_color() {
        let colored = slack_auth_success("T012345", true);
        assert!(colored.starts_with("\u{1b}[32m✓ Slack access ready\u{1b}[0m"));
        assert!(colored.contains("Workspace T012345 · credential saved to Keychain"));

        let plain = slack_auth_success("T012345", false);
        assert_eq!(
            plain,
            "✓ Slack access ready\n  Workspace T012345 · credential saved to Keychain"
        );
        assert!(!plain.contains("\u{1b}["));
    }

    #[test]
    fn login_uses_org_not_tenant() {
        let cli = Cli::try_parse_from(["pentagon", "auth", "login", "--org", "example-org"])
            .expect("--org should parse");
        assert!(matches!(
            cli.command,
            Command::Auth(super::AuthArgs {
                command: AuthCommand::Login { ref org }
            }) if org == "example-org"
        ));

        assert!(
            Cli::try_parse_from(["pentagon", "auth", "login", "--tenant", "example-org"]).is_err()
        );
    }

    #[test]
    fn composes_agent_creation_with_slack_without_hiding_the_operations() {
        let cli = Cli::try_parse_from([
            "pentagon", "agent", "create", "--name", "Treasury", "--slack",
        ])
        .expect("agent create should parse");

        assert!(matches!(
            cli.command,
            Command::Agent(super::AgentArgs {
                command: super::AgentCommand::Create { slack: true, .. }
            })
        ));
    }
}
