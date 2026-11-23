# MCP Auth Proxy

MCP Auth Proxy sits between MCP clients and MCP servers. It forwards requests to configured HTTP or local stdio servers and supplies the upstream credentials, so clients can connect without storing those credentials themselves.

## Features

- Route requests to multiple HTTP or stdio MCP servers by path prefix.
- Inject static credentials from 1Password, Bitwarden, KeePass, or AWS Secrets Manager.
- Authorize HTTP upstreams with OAuth 2.1, PKCE, and Dynamic Client Registration when supported.
- Manage HTTP servers, tool access profiles, and cached tool lists in a built-in settings page.
- Store OAuth tokens in the OS keychain or an encrypted file.
- Filter `tools/list` and `tools/call` requests through profiles.

## Quick start

You need Rust and Cargo to build from source. Install and sign in to the credential provider you plan to use; for example, the 1Password configuration uses the `op` CLI.

1. Copy the sample configuration and edit it for your upstream:

   ```sh
   cp config.example.toml config.toml
   ```

   Replace the example upstream URL and credential reference with real values. See [Configuration](#configuration) for the available options.

2. Check the configuration and resolve its configured credentials:

   ```sh
   cargo run -- --config config.toml --validate
   ```

   This validates the TOML configuration and resolves credential references declared in it. It does not make a health check request to each MCP upstream.

3. Start the proxy:

   ```sh
   cargo run -- --config config.toml
   ```

   Or build an optimized executable and run it directly:

   ```sh
   cargo build --release
   ./target/release/mcp-auth-proxy --config config.toml
   ```

By default, the proxy listens at `http://127.0.0.1:3100`. Connect an MCP client to the proxy URL using the upstream's configured path prefix, such as `http://127.0.0.1:3100/example` for a prefix of `/example`.

The settings page is at [http://127.0.0.1:3100/settings](http://127.0.0.1:3100/settings). It lists configured servers and cached tools, and lets you add HTTP servers and manage profiles. The settings API also exposes upstreams and cached tools at `GET /settings/upstreams` and `GET /settings/tools`; tools can be refreshed with `POST /settings/tools/{upstream}/refresh`. Profiles and dynamically added HTTP servers have collection and per-name CRUD routes under `/settings/profiles` and `/settings/servers`.

## Configuration

The default config file is `config.toml` in the current working directory. Pass `--config <path>` to use a different file. [config.example.toml](config.example.toml) contains a commented template with examples for each provider and both authentication methods.

### Server

```toml
[server]
host = "127.0.0.1"
port = 3100
# Optional reference resolved by the credential provider for the settings API:
# admin_token_ref = "op://Private/mcp-auth-proxy/admin-token"
# Default is false. Only enable this for dynamic HTTP upstreams when necessary.
# allow_insecure_dynamic_upstreams = false
```

The `/settings` page can be viewed without a token. When an admin token is configured, requests to the settings API require `Authorization: Bearer <token>`. The token can come from `server.admin_token_ref` or the `MCP_AUTH_PROXY_ADMIN_TOKEN` environment variable. If the proxy binds to a non-loopback address without a configured token, it generates a temporary one and prints it to stderr.

The admin token protects the settings API only; it does not authenticate requests sent to MCP routes. Keep the listener on loopback unless another trusted layer controls access. The proxy serves HTTP, so use a TLS-terminating reverse proxy if it must be reached remotely.

HTTP upstreams declared in the TOML file may use `http://` or `https://`. HTTP servers added dynamically through settings must use HTTPS unless they are on loopback; `allow_insecure_dynamic_upstreams = true` disables that restriction.

### Upstreams

Each `[[upstream]]` adds a route. The first path segment selects the upstream and is stripped before the remaining path is forwarded. `path_prefix` must be one path segment, such as `/github` or `/local`.

```toml
[[upstream]]
name = "example"
path_prefix = "/example"
transport = "http"                 # "http" (default) or "stdio"
url = "https://mcp.example.com/mcp" # required for HTTP
log_mcp_traffic = false

[upstream.auth]
method = "static"                   # "static" or "oauth"
header = "Authorization"            # default
prefix = "Bearer"                   # optional; prepended to the credential
credential_ref = "op://Private/example/token"

# Optional extra headers. Each value is resolved by the selected provider.
# [[upstream.auth.extra_headers]]
# header = "X-API-Key"
# prefix = "Token"
# credential_ref = "op://Private/example/api-key"
```

Static credentials are resolved on first use, cached for five minutes, and resolved again after an upstream returns `401`. For HTTP upstreams, extra headers can be used with either static or OAuth authentication.

HTTP upstreams accept `http://` or `https://` URLs. For an HTTP upstream, credentials are injected into the configured headers; any matching client-supplied headers are replaced.

For a local stdio upstream, set `transport = "stdio"`, `command`, and optionally `args` and `env` instead of `url`:

```toml
[[upstream]]
name = "local-tool"
path_prefix = "/local"
transport = "stdio"
command = "npx"
args = ["-y", "@example/mcp-server"]
env = { API_TOKEN = "set-this-in-your-local-config" }
log_mcp_traffic = false

[upstream.auth]
method = "static"
credential_ref = "op://Private/local-tool/token"
```

Replace the sample reference with a real, resolvable credential reference. The child process receives a restricted set of inherited environment variables plus the literal values in `env`; values are not shell-expanded, so keep real secrets out of version control. HTTP auth headers are not delivered over stdio; the shared config schema still requires a static auth block and resolves its credential reference for stdio entries.

### OAuth for HTTP upstreams

OAuth is supported for HTTP upstreams only. The proxy discovers the authorization server using `server_url`, uses PKCE, and performs Dynamic Client Registration when the server offers it. If no registration endpoint is available, configure an existing `client_id`. `client_secret_ref` can point to a confidential client's secret. The first authorization opens a browser (or prints a URL) and listens for the callback on `127.0.0.1` at `redirect_port` (default `8765`).

```toml
[[upstream]]
name = "oauth-server"
path_prefix = "/oauth"
transport = "http"
url = "https://mcp.example.com"

[upstream.auth]
method = "oauth"

[upstream.auth.oauth]
server_url = "https://auth.example.com"
scopes = ["mcp:read"]
# Optional for servers without Dynamic Client Registration:
# client_id = "registered-client-id"
# client_secret_ref = "op://Private/oauth/client-secret"
# token_endpoint_auth_method = "client_secret_basic"
# redirect_port = 8765
# client_name = "mcp-auth-proxy"
```

OAuth refresh tokens and registered client credentials are stored using the configured token storage.

### Credential providers

Select one provider with `[credential_provider]`:

| Type | Setup and reference format |
| --- | --- |
| `onepassword` | Install and sign in to `op`, or set `OP_SERVICE_ACCOUNT_TOKEN`. References use `op://vault/item/field`. |
| `bitwarden` | Install and sign in to `bw`. Use `BW_SESSION`, or `BW_CLIENTID` and `BW_CLIENTSECRET`; a locked vault can be unlocked with `BW_PASSWORD`. References are item names, IDs, or URIs. |
| `keepass` | Set the configured `password_env` (default `KEEPASS_PASSWORD`) and provide `database_path`; `key_file` is optional. References are `entry`, `group/entry`, or `group/entry/field`. |
| `aws_secrets_manager` | Uses the standard AWS credential chain. `region` and `profile` are optional. References are `secret-id` or `secret-id#field.path` for a field in a JSON secret. |

Example KeePass configuration:

```toml
[credential_provider]
type = "keepass"
database_path = "/path/to/passwords.kdbx"
password_env = "KEEPASS_PASSWORD"
# key_file = "/path/to/passwords.key"
```

Example AWS Secrets Manager configuration:

```toml
[credential_provider]
type = "aws_secrets_manager"
region = "eu-central-1" # optional
# profile = "my-aws-profile"
```

### Token storage

OAuth tokens use the OS keychain by default, with an encrypted-file fallback:

```toml
[token_storage]
type = "keychain"
fallback = "encrypted_file"

[token_storage.encrypted_file]
path = "~/.config/mcp-auth-proxy/tokens.enc"
# key_env = "MCP_AUTH_PROXY_TOKEN_KEY"
```

The keychain backend uses macOS Keychain, Windows Credential Manager, or Linux Secret Service. The encrypted-file backend uses AES-256-GCM. If no key environment variable is configured, it creates a separate key file next to the token file; keep both files together. The default encrypted token file is under the platform's user config directory.

### Profiles and persistent data

Profiles restrict which tools may be called through a profile prefix. A profile's `allowed_tools` maps upstream route names (the `path_prefix` segment without its leading slash) to tool names; upstreams omitted from the map expose no tools through that profile. For example, a profile named `readonly` routes through `/readonly/<upstream>/...`:

```json
{
  "name": "readonly",
  "allowed_tools": {
    "example": ["search"]
  }
}
```

Profiles and servers added through the settings page are stored in `data/profiles.json` and `data/servers.json` beside the selected config file. Upstreams declared in the TOML file are read-only in the settings API.

### Traffic logging

`log_mcp_traffic = true` records MCP request and response payloads in the application logs, up to 16 KiB per payload. Tool arguments and results may contain sensitive data, so leave it disabled unless you need it for debugging.

## Command-line options and logs

```text
mcp-auth-proxy [--config <path>] [--validate]
```

- `--config <path>` selects the TOML configuration file (default: `config.toml`).
- `--validate` validates the config and resolves configured credential references, then exits.
- Set `RUST_LOG` to change log filtering, for example `RUST_LOG=debug`.

For release preparation and publishing details, see [release-workflow.md](release-workflow.md).
