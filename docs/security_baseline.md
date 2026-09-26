# VULPHEX Security Baseline

## Assets

- VULPHEX source code.
- API credentials and tokens used for authorized testing.
- Target API information.
- Assessment results and evidence.
- Configuration files.

## Inputs

- Authorized API URL or target.
- OpenAPI or Swagger specification.
- Authentication configuration.
- API requests and parameters.
- Test configuration.

## Trust Boundaries

- Security tester to VULPHEX: commands, targets, specifications, credentials, and configuration enter the tool.
- VULPHEX to target API: assessment requests and authentication data leave the tool for the authorized target.
- VULPHEX to local results and evidence storage: responses, results, and evidence are written to the local file system.

## Sensitive Data

- API keys.
- Access tokens.
- Credentials.
- API responses containing sensitive information.
- Assessment evidence.

## Credentials and Secrets

- Never hard-code secrets.
- Never commit credentials to Git.
- Use environment variables or secure configuration for secrets.
- Redact secrets from logs and reports.

## Dependencies

- Python.
- Typer.
- HTTPX.
- PyYAML.
- Pytest.

## External Interfaces

- Target API.
- OpenAPI or Swagger specification.
- File system.
- CLI.

## Threat Assumptions

- Unauthorized use of VULPHEX must be prevented through authorized scope and configuration.
- Credentials may be exposed if improperly handled.
- Target API responses may contain sensitive information.
- Malformed or unexpected API responses must not cause unsafe behavior.
- VULPHEX itself must not introduce unnecessary security weaknesses.
