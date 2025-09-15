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
import { URL, pathToFileURL } from 'node:url';

// Helper: parse JSON safely
function safeJsonParse(str) {
  try {
    return JSON.parse(str);
  } catch (err) {
    return null;
  }
}

// Helper: parse integer environment variables safely with default
function readIntEnv(name, def) {
  const raw = process.env[name];
  const n = Number.parseInt(raw ?? '', 10);
  return Number.isFinite(n) && n > 0 ? n : def;
}

// Tiny sleep utility for backoff retries
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Read configuration from environment
const PORT = parseInt(process.env.PORT || '8080', 10);
// Read the rest from process.env at runtime (not cached) so tests/config can update without restart

// Debug logger toggled by DEBUG env var ("1", "true", "yes")
function debugLog(...args) {
  const v = String(process.env.DEBUG || '');
  if (v === '1' || /^(true|yes)$/i.test(v)) {
    console.log('[agent-proxy]', ...args);
  }
}

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
  const EXPECTED_AGENT = (process.env.EXPECTED_AGENT || 'https://chatgpt.com').replace(
    /^"|"$/g,
    ''
  );
  const BRIDGE_TOKEN = process.env.BRIDGE_TOKEN || '';
  debugLog('validateRequest: EXPECTED_AGENT', EXPECTED_AGENT, 'BRIDGE_TOKEN set', !!BRIDGE_TOKEN);
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
    'host',
    'content-length',
    'connection',
    'upgrade',
    'proxy-authorization',
    'proxy-authenticate',
    'te',
    'trailer',
    'transfer-encoding',
    'accept-encoding',
  ]);
  for (const [name, value] of Object.entries(headers)) {
    const lower = name.toLowerCase();
    if (forbidden.has(lower)) {
      continue;
    }
    result[name] = value;
  }
  // Force identity encoding to avoid automatic compression and ensure deterministic behavior
  result['Accept-Encoding'] = 'identity';
  // Always set a UA so upstream services can identify this bridge
  if (!result['User-Agent'] && !result['user-agent']) {
    result['User-Agent'] = 'agent-proxy/1.0';
  }
  return result;
}

// ===== OAuth 2.0 Introspection (optional) =====
// Cache for OAuth token introspection results.
// Keyed by a composite of introspection URL + clientId + token to avoid collisions
// across different introspection servers or client credentials (useful in tests).
const tokenCache = new Map(); // cacheKey -> { data, expiresAt }

function getBearerToken(req) {
  const h = req.headers['authorization'] || req.headers['Authorization'];
  if (!h) return null;
  const m = String(h).match(/^Bearer\s+(.+)$/i);
  return m ? m[1] : null;
}

async function oauthIntrospect(token) {
  const url = process.env.OAUTH_INTROSPECTION_URL;
  const clientId = process.env.OAUTH_CLIENT_ID || '';
  const clientSecret = process.env.OAUTH_CLIENT_SECRET || '';
  const cacheTtlMs = readIntEnv('OAUTH_CACHE_TTL_MS', 60000);

  const cacheKey = `${url}::${clientId}::${token}`;
  const now = Date.now();
  const cached = tokenCache.get(cacheKey);
  if (cached && cached.expiresAt > now) {
    debugLog('oauthIntrospect: cache hit');
    return cached.data;
  }
  const basic = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');
  const body = new URLSearchParams({ token, token_type_hint: 'access_token' });
  let resp;
  let lastErr;
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      resp = await fetch(url, {
        method: 'POST',
        headers: {
          Authorization: `Basic ${basic}`,
          'Content-Type': 'application/x-www-form-urlencoded',
          Accept: 'application/json',
        },
        body: body.toString(),
      });
      break;
    } catch (err) {
      lastErr = err;
      if (attempt < 2) {
        await sleep(10 * (attempt + 1));
        continue;
      }
      throw err;
    }
  }
  const text = await resp.text();
  const data = safeJsonParse(text) || {};
  tokenCache.set(cacheKey, { data, expiresAt: now + cacheTtlMs });
  debugLog('oauthIntrospect: status', resp.status, 'active', data.active === true);
  return data;
}

async function validateOAuth(req) {
  if (!process.env.OAUTH_INTROSPECTION_URL) return null; // Disabled by default
  const token = getBearerToken(req);
  if (!token) return 'missing bearer token';
  let data;
  try {
    data = await oauthIntrospect(token);
  } catch (err) {
    debugLog('oauthIntrospect error:', err?.message || err);
    return 'token introspection error';
  }
  if (!data || data.active !== true) return 'inactive or invalid access token';
  const requiredScopes = (process.env.OAUTH_REQUIRED_SCOPES || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  if (requiredScopes.length) {
    const tokenScopes = String(data.scope || '')
      .split(/[\s,]+/)
      .map((s) => s.trim())
      .filter(Boolean);
    const missing = requiredScopes.filter((s) => !tokenScopes.includes(s));
    if (missing.length) return `missing required scope(s): ${missing.join(', ')}`;
  }
  const requiredAud = process.env.OAUTH_REQUIRED_AUDIENCE;
  if (requiredAud) {
    const aud = Array.isArray(data.aud) ? data.aud : [data.aud].filter(Boolean);
    if (!aud.includes(requiredAud)) return 'invalid audience';
  }
  return null;
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
  const REQUEST_TIMEOUT_MS = readIntEnv('REQUEST_TIMEOUT_MS', 25000);
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
    signal: undefined,
  };
  debugLog('performFetch', upperMethod, target);
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
  // Read body once as text to allow safe fallback from malformed JSON
  const rawText = await response.text();
  let data = rawText;
  const contentType = resultHeaders['content-type'] || '';
  if (/application\/json/i.test(contentType) || /\+json/i.test(contentType)) {
    const parsed = safeJsonParse(rawText);
    if (parsed !== null) {
      data = parsed;
    }
  }
  return {
    status: response.status,
    headers: resultHeaders,
    data,
  };
}

// Main HTTP request handler
async function requestHandler(req, res) {
  try {
    // Only allow POST on /action/fetch and GET on /healthz
    const url = new URL(req.url || '/', 'http://localhost');
    debugLog('request', req.method, url.pathname);
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
    const oauthError = await validateOAuth(req);
    if (oauthError) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: oauthError }));
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
    console.error('Unhandled error in requestHandler:', err); // Log full error for diagnostics
    res.writeHead(500, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'internal_server_error' }));
  }
}

// Factory to create a server instance (useful for tests)
export function createServer() {
  return http.createServer((req, res) => {
    // Ensure the handler promise rejections are surfaced
    requestHandler(req, res).catch((err) => {
      console.error('Unhandled error in request handler promise:', err); // Log error for diagnostics
      try {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'internal_server_error' }));
      } catch {}
    });
  });
}

// Only start listening if this file is executed directly (not when imported by tests)
const isMain = (() => {
  try {
    return import.meta.url === pathToFileURL(process.argv[1]).href;
  } catch {
    return true;
  }
})();

if (isMain) {
  const server = createServer();
  server.listen(PORT, () => {
    console.log(`agent‑proxy listening on port ${PORT}`);
    if (process.env.OAUTH_INTROSPECTION_URL) {
      console.log(
        '[agent-proxy] OAuth introspection enabled:',
        process.env.OAUTH_INTROSPECTION_URL
      );
    }
  });
}

// Export configuration that tests may need
export { PORT };
