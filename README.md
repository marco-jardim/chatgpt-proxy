# Agent Proxy

![CI](https://github.com/marco-jardim/chatgpt-proxy/actions/workflows/ci.yml/badge.svg)
[![codecov](https://codecov.io/gh/marco-jardim/chatgpt-proxy/branch/main/graph/badge.svg)](https://codecov.io/gh/marco-jardim/chatgpt-proxy)

![Node.js](https://img.shields.io/badge/Node.js-18%2B%20%7C%2020%2B%20%7C%2022%2B-339933?logo=node.js&logoColor=white)
![Vitest](https://img.shields.io/badge/Tested%20with-Vitest-6E9F18?logo=vitest&logoColor=white)
![Supertest](https://img.shields.io/badge/HTTP%20tests-Supertest-000000)
![Prettier](https://img.shields.io/badge/Code%20style-Prettier-F7B93E?logo=prettier&logoColor=000)

This repository contains a minimal Node.js backend that acts as a secure
bridge for ChatGPT agents. It listens for signed requests from your
custom GPT or Agent and performs outbound HTTP calls on its behalf.

## Features

- **Restricts access to your agent** – requests must include a
  `Signature-Agent` header matching `https://chatgpt.com`. You can
  optionally enforce a shared secret via `X-Bridge-Token`.
- **Proxy to any target** – given a `target` URL and HTTP `method`, the
  server calls the remote API and returns the status, headers and
  response body (JSON or text).
- **Zero dependencies** – uses only Node.js core modules; no need to
  `npm install`.
- **Optional OAuth 2.0** – when configured, requests must include an
  `Authorization: Bearer <token>` header which is validated via a token
  introspection endpoint (RFC 7662). Required scopes and audience can be
  enforced.
- **Debug logging** – set `DEBUG=1` to get verbose, prefixed console logs
  that help diagnose routing, validation, and proxy behavior.

## Usage

Clone or copy this folder into your project. Configure the
environment variables (see `.env.example`) and run:

```
node src/server.js
```

The server exposes two endpoints:

| Method | Path            | Description                                     |
| -----: | --------------- | ----------------------------------------------- |
|  `GET` | `/healthz`      | Returns a simple JSON object `{"ok": true}`.    |
| `POST` | `/action/fetch` | Accepts a JSON payload and proxies the request. |

### Proxying an API request

Send a POST request to `/action/fetch` with the following JSON body:

```json
{
  "target": "https://api.example.com/v1/resource",
  "method": "GET",
  "headers": {
    "Authorization": "Bearer token..."
  },
  "body": null
}
```

Required request headers:

- `Signature-Agent`: must be set to `"https://chatgpt.com"` (the
  surrounding quotes are required by the spec). This identifies the
  caller as the ChatGPT agent.
- `X-Bridge-Token`: value must match `BRIDGE_TOKEN` (if set). This
  ensures only your agent can use this endpoint.
- `Authorization: Bearer <token>`: required only if OAuth is enabled
  (see below). The token will be validated using the configured
  introspection endpoint.

The response will contain a JSON object:

```json
{
  "status": 200,
  "headers": {
    "content-type": "application/json; charset=utf-8",
    "other-header": "..."
  },
  "data": { "the": "response body" }
}
```

### Notes

- **Signature verification** – This example checks the
  `Signature-Agent` header to ensure the request claims to be from
  ChatGPT. It does **not** cryptographically verify the `Signature`
  header. For stronger security, implement RFC 9421 signature
  verification by fetching and caching the public keys from
  `https://chatgpt.com/.well-known/http-message-signatures-directory`.
- **Proxy support** – Outbound requests use Node's built‑in `fetch()`. If
  you need to send traffic through a proxy, set `HTTPS_PROXY` and
  `HTTP_PROXY` environment variables and consider using a library
  such as global-agent or https-proxy-agent. Since this project avoids
  external dependencies, proxy support is not implemented directly.
- **Allowed methods** – Only `GET`, `POST`, `PUT`, `PATCH` and `DELETE`
  are supported. Extend `performFetch()` in `src/server.js` to add
  additional methods if necessary.

## Configuration

Environment variables control behavior. See `.env.example` for a full list.

- `PORT`: HTTP port to listen on (default `8080`).
- `EXPECTED_AGENT`: expected value of the Signature-Agent header
  (default `https://chatgpt.com`).
- `BRIDGE_TOKEN`: shared secret; when set, requests must include
  `X-Bridge-Token` with this exact value.
- `REQUEST_TIMEOUT_MS`: timeout for outbound fetches (default `25000`).
- `DEBUG`: set to `1`, `true`, or `yes` to enable verbose logs.
- `OPEN_MODE`: set to `1`, `true`, or `yes` to bypass all validations and act
  as a transparent proxy. Warning: do not enable this in production.

### OAuth 2.0 (optional)

If you set `OAUTH_INTROSPECTION_URL` (and client credentials), the proxy
will require and validate a bearer token on every `/action/fetch` call.

Supported variables:

- `OAUTH_INTROSPECTION_URL`: RFC 7662 token introspection endpoint URL.
- `OAUTH_CLIENT_ID` / `OAUTH_CLIENT_SECRET`: Basic auth credentials used
  to call the introspection endpoint.
- `OAUTH_REQUIRED_SCOPES`: comma-separated list (e.g. `agent:proxy,write`).
  The token must include all of these scopes.
- `OAUTH_REQUIRED_AUDIENCE`: required audience value; token `aud` must
  include this value.
- `OAUTH_CACHE_TTL_MS`: cache TTL for introspection responses (default
  `60000`).

When OAuth is enabled, any error in bearer parsing, introspection, or
policy checks (scopes/audience) results in `401` with an explanatory
message. The bridge token check (if configured) still applies in
addition to OAuth.

### Open mode (transparent proxy)

If you set `OPEN_MODE=1`, the server skips all validations (`Signature-Agent`,
`X-Bridge-Token`, and OAuth). It will accept requests without those headers and
proxy them as-is. This is handy when using it as a simple connector in Agent
mode, but it is unsafe for exposed environments. Use only in trusted and
isolated setups.

## Testing

You can test the server locally using `curl`:

```bash
export BRIDGE_TOKEN=my-secret
node src/server.js &

curl -X POST http://localhost:8080/action/fetch \
  -H 'Signature-Agent: "https://chatgpt.com"' \
  -H 'X-Bridge-Token: my-secret' \
  -H 'Content-Type: application/json' \
  -d '{"target":"https://jsonplaceholder.typicode.com/todos/1","method":"GET"}'
```

This should return a JSON response containing the todo item from the
placeholder API.

With OAuth enabled, include the bearer token:

```bash
export OAUTH_INTROSPECTION_URL="http://localhost:8081/introspect"
export OAUTH_CLIENT_ID=bridge-client
export OAUTH_CLIENT_SECRET=bridge-secret
export OAUTH_REQUIRED_SCOPES=agent:proxy

curl -X POST http://localhost:8080/action/fetch \
  -H 'Signature-Agent: "https://chatgpt.com"' \
  -H 'X-Bridge-Token: my-secret' \
  -H 'Authorization: Bearer abc.def.ghi' \
  -H 'Content-Type: application/json' \
  -d '{"target":"https://httpbin.org/json","method":"GET"}'
```

Enable debug logs for troubleshooting:

```bash
export DEBUG=1
node src/server.js
```
