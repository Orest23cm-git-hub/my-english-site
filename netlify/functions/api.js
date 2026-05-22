import crypto from 'node:crypto';
import { getStore } from '@netlify/blobs';

const SESSION_SECRET = process.env.SESSION_SECRET || 'change-this-session-secret';
const DEFAULT_SITE_PASS_HASH = process.env.SITE_PASS_HASH || '1b81e88b25c360840af1b52885a53dd68f7f77c93ce02f5e925e78d414a46b9c';
const DEFAULT_ADMIN_PASS_HASH = process.env.ADMIN_PASS_HASH || 'eb46ec27f25d25f53b8f34f2e58f04fccbca548dc41ee1cd65f03c4c08fd8287';
const DEFAULT_WEBHOOK = process.env.DISCORD_WEBHOOK || '';
const STORE_NAME = 'english-auth-state';
const STATE_KEY = 'auth-state';

function sha256(value) {
  return crypto.createHash('sha256').update(String(value)).digest('hex');
}

function json(statusCode, data) {
  return {
    statusCode,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
    },
    body: JSON.stringify(data),
  };
}

function createToken(payload) {
  const body = Buffer.from(JSON.stringify({ ...payload, iat: Date.now() })).toString('base64url');
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(body).digest('base64url');
  return `${body}.${sig}`;
}

function readToken(event) {
  const auth = event.headers.authorization || event.headers.Authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  const [body, sig] = token.split('.');
  if (!body || !sig) return null;
  const expected = crypto.createHmac('sha256', SESSION_SECRET).update(body).digest('base64url');
  if (sig.length !== expected.length) return null;
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
  try {
    return JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
  } catch {
    return null;
  }
}

async function loadState() {
  const store = getStore(STORE_NAME);
  const state = await store.get(STATE_KEY, { type: 'json' });
  if (state) {
    return {
      kv: state.kv || '0',
      visitors: Array.isArray(state.visitors) ? state.visitors : [],
      sitePassHash: state.sitePassHash || DEFAULT_SITE_PASS_HASH,
      adminPassHash: state.adminPassHash || DEFAULT_ADMIN_PASS_HASH,
      webhook: state.webhook || DEFAULT_WEBHOOK,
    };
  }
  const initialState = {
    kv: '0',
    visitors: [],
    sitePassHash: DEFAULT_SITE_PASS_HASH,
    adminPassHash: DEFAULT_ADMIN_PASS_HASH,
    webhook: DEFAULT_WEBHOOK,
  };
  await writeState(initialState);
  return initialState;
}

async function writeState(state) {
  const store = getStore(STORE_NAME);
  await store.setJSON(STATE_KEY, state);
}

function parseBody(event) {
  if (!event.body) return {};
  try {
    return JSON.parse(event.body);
  } catch {
    return {};
  }
}

function getRoute(event) {
  const rawPath = event.path || '';
  const prefix = '/.netlify/functions/api';
  if (rawPath.startsWith(prefix)) return rawPath.slice(prefix.length) || '/';
  if (rawPath.startsWith('/api')) return rawPath.slice('/api'.length) || '/';
  return rawPath || '/';
}

function requireRole(event, role) {
  const token = readToken(event);
  return token && token.role === role ? token : null;
}

function getClientIp(event) {
  const forwarded = event.headers['x-forwarded-for'] || event.headers['X-Forwarded-For'];
  if (forwarded) return forwarded.split(',')[0].trim();
  return event.headers['client-ip'] || '—';
}

async function notifyDiscord(webhook, entry) {
  if (!webhook) return;
  const dt = new Date(entry.time).toLocaleString('uk-UA');
  const content =
    `🔐 **Хтось зайшов на сайт!**\n` +
    `📅 ${dt}\n` +
    `🌐 IP: \`${entry.ip}\`\n` +
    `${entry.mobile ? '📱 Мобільний' : '🖥 Компʼютер'} · ${entry.browser} · ${entry.os}\n` +
    `🖥 Екран: ${entry.screen} · 🌍 Мова: ${entry.lang} · 🕐 ${entry.tz}`;

  try {
    await fetch(webhook, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ content }),
    });
  } catch {
  }
}

export async function handler(event) {
  const route = getRoute(event);
  const method = event.httpMethod;
  const state = await loadState();

  try {
    if (method === 'GET' && route === '/session') {
      const token = readToken(event);
      const valid = Boolean(token && token.role === 'user' && token.kv === state.kv && token.ph === state.sitePassHash);
      return json(200, { ok: true, valid, kv: state.kv });
    }

    if (method === 'POST' && route === '/auth/login') {
      const body = parseBody(event);
      if (sha256(body.password || '') !== state.sitePassHash) return json(403, { ok: false, error: 'Bad password' });
      return json(200, { ok: true, token: createToken({ role: 'user', kv: state.kv, ph: state.sitePassHash }), kv: state.kv });
    }

    if (method === 'POST' && route === '/visit') {
      if (!requireRole(event, 'user')) return json(401, { ok: false, error: 'Unauthorized' });
      const body = parseBody(event);
      const entry = {
        id: crypto.randomBytes(6).toString('hex'),
        time: new Date().toISOString(),
        ip: getClientIp(event),
        ua: event.headers['user-agent'] || body.ua || '—',
        browser: body.browser || '❓ Браузер',
        os: body.os || '❓ OS',
        mobile: Boolean(body.mobile),
        screen: body.screen || '—',
        lang: body.lang || '—',
        tz: body.tz || '—',
        kicked: false,
      };
      state.visitors = [entry, ...state.visitors].slice(0, 300);
      await writeState(state);
      await notifyDiscord(state.webhook, entry);
      return json(200, { ok: true, entry, kv: state.kv });
    }

    if (method === 'POST' && route === '/admin/login') {
      const body = parseBody(event);
      if (sha256(body.password || '') !== state.adminPassHash) return json(403, { ok: false, error: 'Bad admin password' });
      return json(200, { ok: true, token: createToken({ role: 'admin' }) });
    }

    if (method === 'GET' && route === '/admin/visitors') {
      if (!requireRole(event, 'admin')) return json(401, { ok: false, error: 'Unauthorized' });
      return json(200, { ok: true, kv: state.kv, visitors: state.visitors, webhookConfigured: Boolean(state.webhook) });
    }

    if (method === 'POST' && route === '/admin/kick') {
      if (!requireRole(event, 'admin')) return json(401, { ok: false, error: 'Unauthorized' });
      const body = parseBody(event);
      state.kv = String(Number(state.kv || 0) + 1);
      const visitor = state.visitors.find(item => item.id === body.id);
      if (visitor) visitor.kicked = true;
      await writeState(state);
      return json(200, { ok: true, kv: state.kv });
    }

    if (method === 'POST' && route === '/admin/kick-all') {
      if (!requireRole(event, 'admin')) return json(401, { ok: false, error: 'Unauthorized' });
      state.kv = String(Number(state.kv || 0) + 1);
      await writeState(state);
      return json(200, { ok: true, kv: state.kv });
    }

    if (method === 'POST' && route === '/admin/change-pass') {
      if (!requireRole(event, 'admin')) return json(401, { ok: false, error: 'Unauthorized' });
      const body = parseBody(event);
      if (!body.password || String(body.password).length < 3) return json(400, { ok: false, error: 'Password too short' });
      state.sitePassHash = sha256(body.password);
      state.kv = String(Number(state.kv || 0) + 1);
      await writeState(state);
      return json(200, { ok: true, kv: state.kv });
    }

    if (method === 'POST' && route === '/admin/webhook') {
      if (!requireRole(event, 'admin')) return json(401, { ok: false, error: 'Unauthorized' });
      const body = parseBody(event);
      state.webhook = String(body.webhook || '').trim();
      await writeState(state);
      return json(200, { ok: true, configured: Boolean(state.webhook) });
    }

    if (method === 'POST' && route === '/admin/test-webhook') {
      if (!requireRole(event, 'admin')) return json(401, { ok: false, error: 'Unauthorized' });
      const body = parseBody(event);
      const webhook = String(body.webhook || state.webhook || '').trim();
      if (!webhook) return json(400, { ok: false, error: 'Webhook is empty' });
      await fetch(webhook, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ content: '🧪 **Тест** — webhook працює! ✅' }),
      });
      return json(200, { ok: true });
    }

    if (method === 'POST' && route === '/admin/clear-visitors') {
      if (!requireRole(event, 'admin')) return json(401, { ok: false, error: 'Unauthorized' });
      state.visitors = [];
      await writeState(state);
      return json(200, { ok: true });
    }

    return json(404, { ok: false, error: 'Not found' });
  } catch (error) {
    return json(500, { ok: false, error: error.message || 'Server error' });
  }
}
