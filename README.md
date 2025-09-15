# Agent Proxy

This repository contains a minimal Node.js backend that acts as a secure
bridge for ChatGPT agents. It listens for signed requests from your
custom GPT or Agent and performs outbound HTTP calls on its behalf.

## Features

* **Restricts access to your agent** – requests must include a
  `Signature-Agent` header matching `https://chatgpt.com`. You can
  optionally enforce a shared secret via `X-Bridge-Token`.
* **Proxy to any target** – given a `target` URL and HTTP `method`, the
  server calls the remote API and returns the status, headers and
  response body (JSON or text).
* **Zero dependencies** – uses only Node.js core modules; no need to
  `npm install`.

## Usage

Clone or copy this folder into your project. Configure the
environment variables (see `.env.example`) and run:

```
node src/server.js
```

The server exposes two endpoints:

| Method | Path            | Description                                         |
|-------:|----------------|-----------------------------------------------------|
| `GET`  | `/healthz`      | Returns a simple JSON object `{"ok": true}`.         |
| `POST` | `/action/fetch` | Accepts a JSON payload and proxies the request.      |

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

* `Signature-Agent`: must be set to `"https://chatgpt.com"` (the
  surrounding quotes are required by the spec). This identifies the
  caller as the ChatGPT agent.
* `X-Bridge-Token`: value must match `BRIDGE_TOKEN` (if set). This
  ensures only your agent can use this endpoint.

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

* **Signature verification** – This example checks the
  `Signature-Agent` header to ensure the request claims to be from
  ChatGPT. It does **not** cryptographically verify the `Signature`
  header. For stronger security, implement RFC 9421 signature
  verification by fetching and caching the public keys from
  `https://chatgpt.com/.well-known/http-message-signatures-directory`.
* **Proxy support** – Outbound requests use Node's built‑in `fetch()`. If
  you need to send traffic through a proxy, set `HTTPS_PROXY` and
  `HTTP_PROXY` environment variables and consider using a library
  such as global-agent or https-proxy-agent. Since this project avoids
  external dependencies, proxy support is not implemented directly.
* **Allowed methods** – Only `GET`, `POST`, `PUT`, `PATCH` and `DELETE`
  are supported. Extend `performFetch()` in `src/server.js` to add
  additional methods if necessary.

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