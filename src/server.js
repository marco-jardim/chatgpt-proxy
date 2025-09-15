/*
 * agent-proxy/src/server.js
 *
 * Minimal HTTP service written in plain Node.js designed to act as a
 * bridge between a ChatGPT Agent and arbitrary external APIs. The server
 * only responds to requests from the expected agent and user (via a
 * shared secret) but is otherwise free to call any web service on
 * behalf of the agent. This implementation avoids third‑party
 * dependencies so it can run in restricted environments where `npm
 * install` is disabled.
 *
 * Environment variables:
 *   PORT               Port to listen on (default: 8080)
 *   BRIDGE_TOKEN       Shared secret that the agent must include in
 *                      `X-Bridge-Token` header. If omitted, token
 *                      validation is skipped.
 *   EXPECTED_AGENT     Expected value of `Signature-Agent` header
 *                      without quotes (default: https://chatgpt.com)
 *   REQUEST_TIMEOUT_MS Timeout in milliseconds for outbound fetches
 *                      (default: 25000)
 */

import http from 'node:http';
import { URL } from 'node:url';

// Helper: parse JSON safely
function safeJsonParse(str) {
  try {
    return JSON.parse(str);
  } catch (err) {
    return null;
  }
}

// Read configuration from environment
const PORT = parseInt(process.env.PORT || '8080', 10);
const BRIDGE_TOKEN = process.env.BRIDGE_TOKEN || '';
const EXPECTED_AGENT = (process.env.EXPECTED_AGENT || 'https://chatgpt.com').replace(/^"|"$/g, '');
const REQUEST_TIMEOUT_MS = parseInt(process.env.REQUEST_TIMEOUT_MS || '25000', 10);

/**
 * Validate incoming headers to ensure the call originated from the
 * expected ChatGPT agent. Returns an error message string if
 * validation fails, or null on success.
 *
 * The validation logic is intentionally simple: it checks for the
 * presence of the `Signature-Agent` header and optionally verifies a
 * shared secret via `X-Bridge-Token`. You can extend this function
 * to perform additional checks (e.g. nonce replay, signature
 * verification) if desired.
 *
 * @param {http.IncomingMessage} req
 * @returns {string|null}
 */
function validateRequest(req) {
  // Ensure the signature agent header is present. The spec encloses
  // the value in double quotes; remove quotes before comparison.
  const sigAgentRaw = req.headers['signature-agent'];
  if (!sigAgentRaw) {
    return 'missing signature-agent header';
  }
  // Strip surrounding quotes (if any) and compare to expected
  const sigAgent = String(sigAgentRaw).replace(/^"|"$/g, '').trim();
  if (sigAgent !== EXPECTED_AGENT) {
    return `unexpected signature-agent: ${sigAgent}`;
  }
  // If a bridge token is configured, require a matching header
  if (BRIDGE_TOKEN) {
    const providedToken = req.headers['x-bridge-token'];
    if (!providedToken || String(providedToken) !== BRIDGE_TOKEN) {
      return 'invalid or missing X-Bridge-Token';
    }
  }
  return null;
}

/**
 * Sanitize headers passed from the agent to the upstream request. We
 * drop hop‑by‑hop and connection management headers as per RFC 7230 to
 * avoid header injection issues. We also drop any headers that could
 * interfere with the proxy itself.
 *
 * @param {Record<string, string>} headers
 * @returns {Record<string, string>}
 */
function sanitizeOutboundHeaders(headers) {
  const result = {};
  const forbidden = new Set([
    'host', 'content-length', 'connection', 'upgrade',
    'proxy-authorization', 'proxy-authenticate', 'te', 'trailer',
    'transfer-encoding', 'accept-encoding'
  ]);
  for (const [name, value] of Object.entries(headers)) {
    const lower = name.toLowerCase();
    if (forbidden.has(lower)) {
      continue;
    }
    result[name] = value;
  }
  // Always set a UA so upstream services can identify this bridge
  if (!result['User-Agent'] && !result['user-agent']) {
    result['User-Agent'] = 'agent-proxy/1.0';
  }
  return result;
}

/**
 * Handle the proxying of a request. This function expects a
 * payload with the shape `{ target, method, headers?, body? }`. It
 * performs an outbound fetch to the specified target and returns the
 * status code, response headers, and either JSON or text content.
 *
 * @param {object} payload
 * @returns {Promise<{status: number, headers: Record<string, string>, data: any}>}
 */
async function performFetch(payload) {
  const { target, method = 'GET', headers = {}, body } = payload;
  // Validate target
  if (!target || typeof target !== 'string' || !/^https?:\/\//i.test(target)) {
    throw Object.assign(new Error('invalid target'), { statusCode: 400 });
  }
  const upperMethod = String(method).toUpperCase();
  if (!['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(upperMethod)) {
    throw Object.assign(new Error('unsupported method'), { statusCode: 400 });
  }
  const fetchOptions = {
    method: upperMethod,
    headers: sanitizeOutboundHeaders(headers),
    // Only include body for methods that allow it
    body: ['GET', 'DELETE'].includes(upperMethod) ? undefined : body,
    // Set a timeout via AbortController
    signal: undefined
  };
  const controller = new AbortController();
  const timeoutId = setTimeout(() => {
    controller.abort(new Error('fetch timeout'));
  }, REQUEST_TIMEOUT_MS);
  fetchOptions.signal = controller.signal;
  let response;
  try {
    response = await fetch(target, fetchOptions);
  } finally {
    clearTimeout(timeoutId);
  }
  const resultHeaders = {};
  // Convert Headers object to plain object
  response.headers.forEach((value, key) => {
    resultHeaders[key] = value;
  });
  // Attempt to parse JSON; fall back to text
  let data;
  const contentType = resultHeaders['content-type'] || '';
  if (/application\/json/i.test(contentType) || /\+json/i.test(contentType)) {
    try {
      data = await response.json();
    } catch {
      data = await response.text();
    }
  } else {
    data = await response.text();
  }
  return {
    status: response.status,
    headers: resultHeaders,
    data
  };
}

// Main HTTP server
const server = http.createServer(async (req, res) => {
  try {
    // Only allow POST on /action/fetch and GET on /healthz
    const url = new URL(req.url || '/', 'http://localhost');
    if (req.method === 'GET' && url.pathname === '/healthz') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true }));
      return;
    }
    if (!(req.method === 'POST' && url.pathname === '/action/fetch')) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'not_found' }));
      return;
    }
    // Validate headers
    const errorMsg = validateRequest(req);
    if (errorMsg) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: errorMsg }));
      return;
    }
    // Read body
    let bodyBuffer = Buffer.alloc(0);
    for await (const chunk of req) {
      bodyBuffer = Buffer.concat([bodyBuffer, chunk]);
      // Optionally enforce a max size; skip here because not specified
    }
    const bodyString = bodyBuffer.toString('utf8');
    const payload = safeJsonParse(bodyString);
    if (!payload || typeof payload !== 'object') {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'invalid_json' }));
      return;
    }
    // Perform fetch
    let fetchResult;
    try {
      fetchResult = await performFetch(payload);
    } catch (err) {
      const statusCode = err.statusCode || 502;
      res.writeHead(statusCode, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: err.message || 'fetch_error' }));
      return;
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(fetchResult));
  } catch (err) {
    // Catch‑all error handler
    res.writeHead(500, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'internal_server_error', detail: String(err?.message || err) }));
  }
});

server.listen(PORT, () => {
  console.log(`agent‑proxy listening on port ${PORT}`);
});