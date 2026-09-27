import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import crypto from 'crypto';
import path from 'path';
import { fileURLToPath } from 'url';
import { encrypt, decrypt } from './crypto.js';
import { db, getConfig, setConfig, logStat } from './db.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '64kb' }));

if (!getConfig('webhook_enc') && process.env.DISCORD_WEBHOOK) {
  setConfig('webhook_enc', encrypt(process.env.DISCORD_WEBHOOK));
}
if (getConfig('kill_switch') === null) setConfig('kill_switch', 'off');

const getWebhook = () => {
  const enc = getConfig('webhook_enc');
  return enc ? decrypt(enc) : null;
};
const isKilled = () => getConfig('kill_switch') === 'on';
const hashKey = (k) => crypto.createHash('sha256').update(k).digest('hex');
const forwardRateLimit = Number.parseInt(process.env.FORWARD_RATE_LIMIT || '120', 10);

function validateApiKey(req, res, next) {
  const key = req.headers['x-api-key'];
  if (!key) return res.status(401).json({ error: 'missing api key' });
  const row = db.prepare('SELECT * FROM api_keys WHERE key_hash = ? AND revoked = 0').get(hashKey(key));
  if (!row) { logStat(req.ip, 401, 'bad_key'); return res.status(401).json({ error: 'invalid key' }); }
  req.apiKeyId = row.id;
  next();
}

const forwardLimiter = rateLimit({
  windowMs: 60_000,
  max: Number.isFinite(forwardRateLimit) && forwardRateLimit > 0 ? forwardRateLimit : 120,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => String(req.apiKeyId),
  handler: (req, res) => {
    logStat(req.ip, 429, 'rate_limited_local');
    res.status(429).json({
      error: 'local rate limit',
      source: 'protector',
      retry_after: res.getHeader('Retry-After') || '60'
    });
  }
});

function validatePayload(body) {
  if (typeof body !== 'object' || body === null) return { ok: false, reason: 'not object' };
  const out = {};
  if (typeof body.content === 'string') out.content = body.content.slice(0, 2000);
  if (typeof body.username === 'string') out.username = body.username.slice(0, 80);
  if (typeof body.avatar_url === 'string') out.avatar_url = body.avatar_url;
  if (Array.isArray(body.embeds)) out.embeds = body.embeds.slice(0, 10);
  if (!out.content && !out.embeds) return { ok: false, reason: 'empty' };
  return { ok: true, value: out };
}

const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function postWebhook(webhook, payload) {
  let retryAfter = 1;

  for (let attempt = 0; attempt < 3; attempt += 1) {
    const response = await fetch(webhook, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    if (response.status !== 429) return { response, retryAfter: null };

    const body = await response.json().catch(() => null);
    retryAfter = Number(body?.retry_after ?? response.headers.get('retry-after') ?? 1);
    if (!Number.isFinite(retryAfter) || retryAfter < 0) retryAfter = 1;
    if (attempt < 2) await wait(Math.min(Math.max(retryAfter, 0.05), 10) * 1000);
  }

  return { response: null, retryAfter };
}

app.post('/api/send', validateApiKey, forwardLimiter, async (req, res) => {
  if (isKilled()) {
    logStat(req.ip, 503, 'killed');
    return res.status(503).json({ error: 'forwarding disabled' });
  }
  const v = validatePayload(req.body);
  if (!v.ok) {
    logStat(req.ip, 400, 'invalid:' + v.reason);
    return res.status(400).json({ error: 'invalid payload: ' + v.reason });
  }

  const webhook = getWebhook();
  if (!webhook) {
    logStat(req.ip, 500, 'no_webhook');
    return res.status(500).json({ error: 'webhook not configured' });
  }

  try {
    const { response: r, retryAfter } = await postWebhook(webhook, v.value);
    if (!r) {
      logStat(req.ip, 429, 'rate_limited_discord');
      return res.status(429).json({ error: 'discord rate limit', source: 'discord', retry_after: retryAfter });
    }
    logStat(req.ip, r.status, r.ok ? 'forwarded' : 'discord_error');
    if (!r.ok) return res.status(502).json({ error: 'discord rejected', status: r.status });
    return res.json({ ok: true });
  } catch (e) {
    logStat(req.ip, 500, 'fetch_fail');
    return res.status(502).json({ error: 'forward failed' });
  }
});

function requireAdmin(req, res, next) {
  const token = req.headers['x-admin-token'] || req.query.token;
  if (!token || token !== process.env.ADMIN_TOKEN) return res.status(401).json({ error: 'unauthorized' });
  next();
}

app.get('/api/health', requireAdmin, async (req, res) => {
  const webhook = getWebhook();
  if (!webhook) return res.json({ status: 'unconfigured' });
  try {
    const r = await fetch(webhook, { method: 'GET' });
    res.json({ status: r.ok ? 'healthy' : 'degraded', http: r.status });
  } catch {
    res.json({ status: 'unreachable' });
  }
});

app.post('/admin/test-webhook', requireAdmin, async (req, res) => {
  const webhook = getWebhook();
  if (!webhook) return res.status(400).json({ error: 'webhook not configured' });

  try {
    const { response: r, retryAfter } = await postWebhook(webhook, {
      content: 'Webhook Protector test message'
    });
    if (!r) {
      logStat(req.ip, 429, 'rate_limited_discord_admin_test');
      return res.status(429).json({ error: 'discord rate limit', source: 'discord', retry_after: retryAfter });
    }
    if (!r.ok) return res.status(502).json({ error: 'discord rejected', status: r.status });

    logStat(req.ip, r.status, 'admin_test_forwarded');
    return res.json({ ok: true, status: 'test message sent' });
  } catch {
    logStat(req.ip, 500, 'admin_test_fetch_fail');
    return res.status(502).json({ error: 'webhook test failed' });
  }
});

app.post('/admin/keys', requireAdmin, (req, res) => {
  const key = crypto.randomBytes(24).toString('hex');
  const label = String(req.body?.label || 'default').slice(0, 64);
  db.prepare('INSERT INTO api_keys(key_hash,label,created_at) VALUES(?,?,?)')
    .run(hashKey(key), label, Date.now());
  res.json({ key, label, note: 'store this now — only the hash is kept' });
});

app.get('/admin/keys', requireAdmin, (req, res) => {
  const rows = db.prepare('SELECT id,label,created_at,revoked FROM api_keys ORDER BY id DESC').all();
  res.json(rows);
});

app.post('/admin/keys/:id/revoke', requireAdmin, (req, res) => {
  db.prepare('UPDATE api_keys SET revoked = 1 WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

app.get('/admin/stats', requireAdmin, (req, res) => {
  const total = db.prepare('SELECT COUNT(*) c FROM stats').get().c;
  const blocked = db.prepare("SELECT COUNT(*) c FROM stats WHERE status IN (401,429,400,503)").get().c;
  const rateEvents = db.prepare("SELECT COUNT(*) c FROM stats WHERE event LIKE 'rate%'").get().c;
  const recentLog = db.prepare('SELECT ts,ip,status,event FROM stats ORDER BY id DESC LIMIT 100').all();
  res.json({ total, blocked, rateEvents, recentLog });
});

app.post('/admin/rotate', requireAdmin, (req, res) => {
  const url = String(req.body?.webhook || '').trim();
  if (!/^https:\/\/discord(app)?\.com\/api\/webhooks\//.test(url)) {
    return res.status(400).json({ error: 'not a discord webhook url' });
  }
  setConfig('webhook_enc', encrypt(url));
  logStat(req.ip, 200, 'rotated');
  res.json({ ok: true });
});

app.post('/admin/kill', requireAdmin, (req, res) => {
  setConfig('kill_switch', req.body?.on ? 'on' : 'off');
  res.json({ ok: true, kill_switch: getConfig('kill_switch') });
});

app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));

app.listen(process.env.PORT || 8080, () => {
  console.log('protector up on :' + (process.env.PORT || 8080));
});
