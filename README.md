# Pentagon CLI

`pentagon` is the command-line interface for Pentagon.

## Install

Install the tested pilot build directly from source:

```console
cargo install --git https://github.com/arlington-labs/pentagon-cli.git --rev f11ac3dfca9200225ca854f04dffb793546860f3 --locked
pentagon --version
```

This requires Rust 1.91 or newer. If Rust is already installed through `rustup`,
`rustup update stable` supplies the required toolchain.

To reinstall the tested build over an existing installation:

```console
cargo install --git https://github.com/arlington-labs/pentagon-cli.git --rev f11ac3dfca9200225ca854f04dffb793546860f3 --locked --force
pentagon --version
```

## Create and connect an agent

```console
pentagon auth login --org <organization-slug>
pentagon slack auth login
pentagon agent create --name '<agent name>' --slack
```

For a repeatable agent definition, pass a YAML file instead:

```yaml
name: Treasury Operations
model: openai/gpt-5.6-terra
color: "#123abc"
instructions: |
  Keep treasury reconciliations current and explain every exception.
slack: true
```

```console
pentagon agent create --config agent.yaml
```

`name`, `model`, `color`, and `slack` are also available as flags. Use
`--instructions FILE` for longer instructions; explicit flags override the
corresponding YAML values. An omitted color is chosen from Pentagon's agent
color palette, omitted instructions are empty, and Slack setup runs only with
`--slack`.
When `model` is omitted, Pentagon resolves the request to a concrete supported
model before creating the agent; agent configuration and status always report
that actual model. Model identifiers come from Pentagon's live certified
inference catalog.

`pentagon slack auth login` links to Slack's app settings page. Under **Your
App Configuration Tokens**, choose **Generate Token** for the target workspace
and paste the `xoxe-…` refresh token into the CLI's hidden prompt. Use a durable
Slack administrator or app-builder identity with MFA.

`pentagon agent create` creates the Pentagon agent first
and then begins its independently resumable Slack setup. After registering the
new app with Pentagon, the CLI waits until Pentagon's event endpoint answers
Slack's verification handshake, applies Event Subscriptions, and opens Slack's
normal app installation/administrator approval screen. If
approval is pending or any Slack step fails, the Pentagon agent remains intact
and setup can be resumed with `pentagon slack create --agent
<id-or-exact-name>`.

`pentagon slack status --agent …` reports the resumable create/connect attempt.
The CLI currently exposes only the Slack operations required to create and
connect an agent.

## Help and recovery

Every command supports `-h` and `--help`:

```console
pentagon --help
pentagon agent create --help
pentagon slack --help
```

- Interrupted Slack setup: run `pentagon slack create --agent
  <id-or-exact-name>` to resume the existing app.
- Ambiguous agent name: use the agent UUID shown by `pentagon agent list`.
- Revoked local Slack credential: generate another app-configuration token and
  run `pentagon slack auth login` again. Existing agents keep running.
- `pentagon slack auth logout` removes the local Slack configuration credential.
- `pentagon auth logout` revokes the Pentagon device and removes its local
  credential.

## Security boundary

- Pentagon login uses browser-approved, scoped device authorization.
- Slack configuration tokens are read through hidden terminal input.
- Slack refresh credentials live only in the operating-system credential store.
- Slack access credentials remain in memory for one command.
- Neither Slack configuration credential may enter Pentagon requests, files,
  logs, diagnostics, telemetry, crash reports, or command output.
- Pentagon stores the individual app's client/signing secrets and installed bot
  token because those credentials are required to operate that agent.
- The Slack workspace must match the organization configured by Pentagon.
- The CLI connects through the organization's Pentagon-owned endpoint; the
  backend decides whether that organization is authorized to use each feature.
- API overrides are restricted to loopback addresses for local development.

See [SECURITY.md](SECURITY.md) for reporting requirements.

## Development

```console
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```
