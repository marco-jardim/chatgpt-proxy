import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from 'vitest';
import http from 'node:http';
import { createServer as createProxyServer } from '../src/server.js';
import supertest from 'supertest';

// Helper to start a simple upstream mock server
function startUpstream(handler) {
  return new Promise((resolve) => {
    const srv = http.createServer(handler);
    srv.listen(0, () => {
      const address = srv.address();
      const port = typeof address === 'string' ? 0 : address.port;
      resolve({
        server: srv,
        url: `http://127.0.0.1:${port}`,
        port,
      });
    });
  });
}

// Start the proxy server per test suite
let proxy;
let request;
let introspect;

const EXPECTED_AGENT = 'https://chatgpt.com';
const BRIDGE_TOKEN = 'test-token';

beforeAll(async () => {
  // Set env that server reads at module init time
  process.env.EXPECTED_AGENT = EXPECTED_AGENT;
  process.env.BRIDGE_TOKEN = BRIDGE_TOKEN;
  process.env.PORT = '0';

  proxy = createProxyServer();
  await new Promise((resolve) => proxy.listen(0, resolve));
  const address = proxy.address();
  const port = typeof address === 'string' ? 0 : address.port;
  request = supertest(`http://127.0.0.1:${port}`);
});

afterAll(async () => {
  await new Promise((resolve) => proxy.close(resolve));
});

beforeEach(() => {
  delete process.env.OAUTH_INTROSPECTION_URL;
  delete process.env.OAUTH_CLIENT_ID;
  delete process.env.OAUTH_CLIENT_SECRET;
  delete process.env.OAUTH_REQUIRED_SCOPES;
  delete process.env.OAUTH_REQUIRED_AUDIENCE;
});

describe('health endpoint', () => {
  it('returns ok', async () => {
    const res = await request.get('/healthz');
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toMatch(/application\/json/);
    expect(res.body).toEqual({ ok: true });
  });
});

describe('routing and validation', () => {
  it('returns 404 for unknown route', async () => {
    const res = await request.get('/');
    expect(res.status).toBe(404);
    expect(res.body.error).toBe('not_found');
  });

  it('requires signature-agent header', async () => {
    const res = await request
      .post('/action/fetch')
      .send({})
      .set('Content-Type', 'application/json');
    expect(res.status).toBe(401);
    expect(res.body.error).toMatch(/missing signature-agent/i);
  });

  it('rejects invalid signature-agent', async () => {
    const res = await request
      .post('/action/fetch')
      .send({})
      .set('Content-Type', 'application/json')
      .set('Signature-Agent', '"https://example.com"')
      .set('X-Bridge-Token', BRIDGE_TOKEN);
    expect(res.status).toBe(401);
    expect(res.body.error).toMatch(/unexpected signature-agent/);
  });

  it('requires token when configured', async () => {
    // No OAuth yet, still uses bridge token
    const res = await request
      .post('/action/fetch')
      .send({})
      .set('Content-Type', 'application/json')
      .set('Signature-Agent', `"${EXPECTED_AGENT}"`);
    expect(res.status).toBe(401);
    expect(res.body.error).toMatch(/X-Bridge-Token/);
  });

  it('rejects invalid json', async () => {
    const res = await request
      .post('/action/fetch')
      .set('Content-Type', 'application/json')
      .set('Signature-Agent', `"${EXPECTED_AGENT}"`)
      .set('X-Bridge-Token', BRIDGE_TOKEN)
      .send('not-json');
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_json');
  });
});

describe('proxying behavior', () => {
  it('proxies a JSON GET and returns data', async () => {
    const upstream = await startUpstream((req, res) => {
      if (req.url === '/data' && req.method === 'GET') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ hello: 'world' }));
      } else {
        res.writeHead(404);
        res.end();
      }
    });
    const res = await request
      .post('/action/fetch')
      .set('Content-Type', 'application/json')
      .set('Signature-Agent', `"${EXPECTED_AGENT}"`)
      .set('X-Bridge-Token', BRIDGE_TOKEN)
      .send({ target: `${upstream.url}/data`, method: 'GET' });

    upstream.server.close();

    expect(res.status).toBe(200);
    expect(res.body.status).toBe(200);
    expect(res.body.data).toEqual({ hello: 'world' });
  });

  it('handles non-JSON text response', async () => {
    const upstream = await startUpstream((req, res) => {
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end('plain');
    });
    const res = await request
      .post('/action/fetch')
      .set('Content-Type', 'application/json')
      .set('Signature-Agent', `"${EXPECTED_AGENT}"`)
      .set('X-Bridge-Token', BRIDGE_TOKEN)
      .send({ target: `${upstream.url}/`, method: 'GET' });

    upstream.server.close();

    expect(res.status).toBe(200);
    expect(res.body.status).toBe(200);
    expect(res.body.data).toBe('plain');
  });

  it('returns 400 on invalid target', async () => {
    const res = await request
      .post('/action/fetch')
      .set('Content-Type', 'application/json')
      .set('Signature-Agent', `"${EXPECTED_AGENT}"`)
      .set('X-Bridge-Token', BRIDGE_TOKEN)
      .send({ target: 'ftp://example.com', method: 'GET' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid target');
  });

  it('returns 400 on unsupported method', async () => {
    const res = await request
      .post('/action/fetch')
      .set('Content-Type', 'application/json')
      .set('Signature-Agent', `"${EXPECTED_AGENT}"`)
      .set('X-Bridge-Token', BRIDGE_TOKEN)
      .send({ target: 'http://example.com', method: 'OPTIONS' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('unsupported method');
  });

  it('falls back to text when upstream JSON is invalid', async () => {
    const upstream = await startUpstream((req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end('not json');
    });
    const res = await request
      .post('/action/fetch')
      .set('Content-Type', 'application/json')
      .set('Signature-Agent', `"${EXPECTED_AGENT}"`)
      .set('X-Bridge-Token', BRIDGE_TOKEN)
      .send({ target: `${upstream.url}/`, method: 'GET' });

    upstream.server.close();

    expect(res.status).toBe(200);
    expect(res.body.status).toBe(200);
    expect(res.body.data).toBe('not json');
  });

  it('sanitizes forbidden headers and sets User-Agent', async () => {
    const upstream = await startUpstream((req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ headers: req.headers }));
    });
    const payloadHeaders = {
      'Accept-Encoding': 'gzip',
      Host: 'malicious.example',
      'Content-Length': '9999',
      Connection: 'keep-alive',
      'X-Test': 'abc',
    };
    const res = await request
      .post('/action/fetch')
      .set('Content-Type', 'application/json')
      .set('Signature-Agent', `"${EXPECTED_AGENT}"`)
      .set('X-Bridge-Token', BRIDGE_TOKEN)
      .send({ target: `${upstream.url}/`, method: 'GET', headers: payloadHeaders });

    upstream.server.close();

    expect(res.status).toBe(200);
    const echoed = res.body.data.headers;
    // Accept-Encoding is forced to identity by the proxy for determinism
    expect(echoed['accept-encoding']).toBe('identity');
    // Custom header should pass through
    expect(echoed['x-test']).toBe('abc');
    // UA should be our bridge UA
    expect(echoed['user-agent']).toBe('agent-proxy/1.0');
  });

  it('times out slow upstream requests and returns 502', async () => {
    const upstream = await startUpstream((req, res) => {
      setTimeout(() => {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('late');
      }, 300);
    });

    const origTimeout = process.env.REQUEST_TIMEOUT_MS;
    process.env.REQUEST_TIMEOUT_MS = '50';
    const res = await request
      .post('/action/fetch')
      .set('Content-Type', 'application/json')
      .set('Signature-Agent', `"${EXPECTED_AGENT}"`)
      .set('X-Bridge-Token', BRIDGE_TOKEN)
      .send({ target: `${upstream.url}/`, method: 'GET' });
    process.env.REQUEST_TIMEOUT_MS = origTimeout;

    upstream.server.close();

    expect(res.status).toBe(502);
    expect(typeof res.body.error).toBe('string');
  });
});

describe('oauth introspection', () => {
  afterEach(async () => {
    if (introspect) {
      await new Promise((r) => introspect.server.close(r));
      introspect = undefined;
    }
  });

  it('rejects missing bearer token when OAuth is enabled', async () => {
    introspect = await startUpstream((req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ active: true }));
    });
    process.env.OAUTH_INTROSPECTION_URL = `${introspect.url}/introspect`;
    process.env.OAUTH_CLIENT_ID = 'id';
    process.env.OAUTH_CLIENT_SECRET = 'secret';

    const res = await request
      .post('/action/fetch')
      .set('Content-Type', 'application/json')
      .set('Signature-Agent', `"${EXPECTED_AGENT}"`)
      .set('X-Bridge-Token', BRIDGE_TOKEN)
      .send({ target: 'http://example.com', method: 'GET' });

    expect(res.status).toBe(401);
    expect(res.body.error).toMatch(/missing bearer token/);
  });

  it('rejects inactive token', async () => {
    introspect = await startUpstream((req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ active: false }));
    });
    process.env.OAUTH_INTROSPECTION_URL = `${introspect.url}/introspect`;
    process.env.OAUTH_CLIENT_ID = 'id';
    process.env.OAUTH_CLIENT_SECRET = 'secret';

    const res = await request
      .post('/action/fetch')
      .set('Content-Type', 'application/json')
      .set('Signature-Agent', `"${EXPECTED_AGENT}"`)
      .set('X-Bridge-Token', BRIDGE_TOKEN)
      .set('Authorization', 'Bearer abc')
      .send({ target: 'http://example.com', method: 'GET' });

    expect(res.status).toBe(401);
    expect(res.body.error).toMatch(/inactive or invalid/);
  });

  it('rejects when required scopes are missing', async () => {
    introspect = await startUpstream((req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ active: true, scope: 'read other' }));
    });
    process.env.OAUTH_INTROSPECTION_URL = `${introspect.url}/introspect`;
    process.env.OAUTH_CLIENT_ID = 'id';
    process.env.OAUTH_CLIENT_SECRET = 'secret';
    process.env.OAUTH_REQUIRED_SCOPES = 'agent:proxy,write';

    const res = await request
      .post('/action/fetch')
      .set('Content-Type', 'application/json')
      .set('Signature-Agent', `"${EXPECTED_AGENT}"`)
      .set('X-Bridge-Token', BRIDGE_TOKEN)
      .set('Authorization', 'Bearer abc')
      .send({ target: 'http://example.com', method: 'GET' });

    expect(res.status).toBe(401);
    expect(res.body.error).toMatch(/missing required scope/);
  });

  it('accepts valid token with scope and audience', async () => {
    introspect = await startUpstream((req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ active: true, scope: 'agent:proxy', aud: ['chatgpt-proxy'] }));
    });
    process.env.OAUTH_INTROSPECTION_URL = `${introspect.url}/introspect`;
    process.env.OAUTH_CLIENT_ID = 'id';
    process.env.OAUTH_CLIENT_SECRET = 'secret';
    process.env.OAUTH_REQUIRED_SCOPES = 'agent:proxy';
    process.env.OAUTH_REQUIRED_AUDIENCE = 'chatgpt-proxy';

    const upstream = await startUpstream((req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true }));
    });
    const res = await request
      .post('/action/fetch')
      .set('Content-Type', 'application/json')
      .set('Signature-Agent', `"${EXPECTED_AGENT}"`)
      .set('X-Bridge-Token', BRIDGE_TOKEN)
      .set('Authorization', 'Bearer abc')
      .send({ target: `${upstream.url}/`, method: 'GET' });

    upstream.server.close();
    expect(res.status).toBe(200);
    expect(res.body.status).toBe(200);
    expect(res.body.data).toEqual({ ok: true });
  });

  it('returns 401 when introspection endpoint is unreachable', async () => {
    // Point to a non-listening port to trigger network error and retries
    process.env.OAUTH_INTROSPECTION_URL = 'http://127.0.0.1:65535/introspect';
    process.env.OAUTH_CLIENT_ID = 'id';
    process.env.OAUTH_CLIENT_SECRET = 'secret';

    const res = await request
      .post('/action/fetch')
      .set('Content-Type', 'application/json')
      .set('Signature-Agent', `"${EXPECTED_AGENT}"`)
      .set('X-Bridge-Token', BRIDGE_TOKEN)
      .set('Authorization', 'Bearer abc')
      .send({ target: 'http://example.com', method: 'GET' });

    expect(res.status).toBe(401);
    expect(String(res.body.error)).toMatch(/introspection/i);
  });
});
