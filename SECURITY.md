# Security

Do not open a public issue for a suspected vulnerability or credential leak.
Use GitHub's private vulnerability reporting for this repository, or contact
Pentagon through an established private support channel.

## Credential invariants

The following values must never appear in command arguments, configuration
files, resume journals, logs, diagnostics, telemetry, panic output, fixtures, or
test snapshots:

- Pentagon access or refresh credentials;
- Slack app-configuration access or refresh credentials;
- Slack app client secrets or signing secrets;
- Slack bot tokens.

Tests use unmistakably fake sentinel values and must prove redaction for raw,
prefixed, URL-encoded, JSON-escaped, shell-quoted, and error-wrapped forms.

Installations are built from a reviewed source revision. This repository does
not publish binary releases yet.
