require('dotenv').config();
const express = require('express');
const QRCode = require('qrcode');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { TelegramClient, Api } = require('telegram');
const { StringSession } = require('telegram/sessions');

const apiId = parseInt(process.env.API_ID, 10);
const apiHash = process.env.API_HASH;
const PORT = parseInt(process.env.PORT || '3000', 10);
const SESSION_FILE = path.resolve('./session.txt');
const DATA_FILE = path.resolve('./telegram-data.json');
const PANEL_PASSWORD = String(process.env.PANEL_PASSWORD || '').trim();
const MAX_HISTORY = 1200;
const MAX_TEMPLATES = 100;

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '300kb' }));
app.use(express.static(path.resolve('public')));

let client;
let passwordResolver = null;
let authWatchTimer = null;
let loginAttempt = 0;
let state = { status: 'idle', qr: null, needPassword: false, error: null };
let panelTokens = new Set();
let loginAttempts = new Map();
let dialogMap = new Map();
let folderMap = new Map();
let loops = new Map();
let loopSeq = 1;
let history = [];
let templates = [];
let nextHistoryId = 1;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function readData() {
  try {
    if (!fs.existsSync(DATA_FILE)) return { loops: [], templates: [], history: [], nextHistoryId: 1, loopSeq: 1 };
    const raw = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
    return raw && typeof raw === 'object' ? raw : {};
  } catch (e) {
    console.error('Data load failed:', e.message);
    return {};
  }
}
function saveData() {
  const payload = {
    loops: [...loops.values()].map((l) => ({
      id: l.id, text: l.text, entities: l.entities, groups: l.groups.map((g) => ({ chatId: g.chatId, title: g.title, sent: g.sent, error: g.error, disabled: g.disabled })),
      intervalSec: l.intervalSec, gapSec: l.gapSec, maxRounds: l.maxRounds, round: l.round, sent: l.sent,
      running: l.running, paused: l.paused, lastSent: l.lastSent, lastError: l.lastError, nextAt: l.nextAt,
      startAt: l.startAt, createdAt: l.createdAt, updatedAt: Date.now()
    })),
    templates: templates.slice(0, MAX_TEMPLATES),
    history: history.slice(0, MAX_HISTORY),
    nextHistoryId,
    loopSeq,
  };
  const tmp = DATA_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(payload, null, 2));
  fs.renameSync(tmp, DATA_FILE);
}
function safeText(v, max = 4096) { return String(v ?? '').slice(0, max); }
function validateText(text) {
  if (!text || !String(text).trim()) return 'Message cannot be empty.';
  if (String(text).length > 4096) return 'Message cannot exceed 4096 characters.';
  return null;
}
function makeToken() { return crypto.randomBytes(32).toString('hex'); }
function panelAllowed(req) {
  if (!PANEL_PASSWORD) return true;
  const token = req.headers['x-panel-token'] || req.cookies?.panelToken;
  return token && panelTokens.has(String(token));
}
function panelGuard(req, res, next) {
  if (panelAllowed(req)) return next();
  res.status(401).json({ error: 'Panel authentication required.' });
}
function clientGuard(req, res, next) {
  if (!panelAllowed(req)) return res.status(401).json({ error: 'Panel authentication required.' });
  if (state.status !== 'connected') return res.status(401).json({ error: 'Connect your Telegram account first.' });
  next();
}
function publicState() { return { status: state.status, qr: state.qr, needPassword: state.needPassword, error: state.error }; }

/* ---------------- PANEL AUTH ---------------- */
app.get('/api/panel/status', (req, res) => res.json({ required: !!PANEL_PASSWORD, authenticated: panelAllowed(req) }));
app.post('/api/panel/login', (req, res) => {
  if (!PANEL_PASSWORD) return res.json({ ok: true, required: false });
  const ip = req.ip || 'unknown';
  const now = Date.now();
  const a = loginAttempts.get(ip) || { count: 0, reset: now + 15 * 60 * 1000 };
  if (now > a.reset) { a.count = 0; a.reset = now + 15 * 60 * 1000; }
  if (a.count >= 8) return res.status(429).json({ error: 'Too many login attempts. Try again later.' });
  if (String(req.body?.password || '') !== PANEL_PASSWORD) { a.count++; loginAttempts.set(ip, a); return res.status(401).json({ error: 'Incorrect panel password.' }); }
  a.count = 0; loginAttempts.set(ip, a);
  const token = makeToken(); panelTokens.add(token);
  res.json({ ok: true, token });
});
app.post('/api/panel/logout', (req, res) => { const token = req.headers['x-panel-token']; if (token) panelTokens.delete(String(token)); res.json({ ok: true }); });

/* ---------------- LOGIN ---------------- */
function createClient(sessionString = '') {
  return new TelegramClient(new StringSession(sessionString), apiId, apiHash, { connectionRetries: 2 });
}


function stopAuthWatcher() {
  if (authWatchTimer) {
    clearInterval(authWatchTimer);
    authWatchTimer = null;
  }
}

function startAuthWatcher(attempt) {
  stopAuthWatcher();
  const check = async () => {
    if (attempt !== loginAttempt || !client || state.status === 'connected') return;
    try {
      if (!client.connected) return;
      if (await client.checkAuthorization()) {
        if (attempt !== loginAttempt) return;
        stopAuthWatcher();
        fs.writeFileSync(SESSION_FILE, client.session.save(), { mode: 0o600 });
        state = { status: 'connected', qr: null, needPassword: false, error: null };
        passwordResolver = null;
        await resumePersistedLoops();
      }
    } catch (_) {
      // The QR/sign-in flow owns the connection lifecycle. A transient
      // checkAuthorization failure must not abort the login flow.
    }
  };
  check();
  authWatchTimer = setInterval(check, 800);
}

async function init() {
  stopAuthWatcher();
  if (!apiId || !apiHash) throw new Error('API_ID and API_HASH are required in .env');
  const saved = fs.existsSync(SESSION_FILE) ? fs.readFileSync(SESSION_FILE, 'utf8').trim() : '';
  client = createClient(saved);
  await client.connect();
  if (saved && (await client.checkAuthorization())) {
    state.status = 'connected';
    setTimeout(() => resumePersistedLoops(), 500);
  }
}

app.post('/api/login', panelGuard, async (req, res) => {
  if (state.status === 'connected') return res.json({ ok: true });
  if (state.status === 'waiting') return res.json({ ok: true });

  const attempt = ++loginAttempt;
  stopAuthWatcher();
  state = { status: 'waiting', qr: null, needPassword: false, error: null };
  res.json({ ok: true });

  (async () => {
    try {
      if (!client) client = createClient('');
      if (!client.connected) await client.connect();

      if (await client.checkAuthorization()) {
        if (attempt !== loginAttempt) return;
        state = { status: 'connected', qr: null, needPassword: false, error: null };
        await resumePersistedLoops();
        return;
      }

      const signInPromise = client.signInUserWithQrCode({ apiId, apiHash }, {
        qrCode: async (code) => {
          if (attempt !== loginAttempt) return;
          const url = 'tg://login?token=' + code.token.toString('base64url');
          state.qr = await QRCode.toDataURL(url, { width: 320, margin: 2 });

          // Do not wait for signInUserWithQrCode() to resolve before
          // detecting authorization. Telegram may authorize the device first
          // while the GramJS promise is still waiting on the next QR cycle.
          startAuthWatcher(attempt);
        },
        password: async () => {
          if (attempt !== loginAttempt) throw new Error('Login cancelled.');
          stopAuthWatcher();
          state.needPassword = true;
          return new Promise((resolve) => { passwordResolver = resolve; });
        },
        onError: async (e) => {
          if (attempt === loginAttempt) state.error = e.message;
          return true;
        },
      });

      // Also start the watcher here in case Telegram authorizes before the
      // first QR callback finishes.
      startAuthWatcher(attempt);

      try {
        await signInPromise;
      } catch (e) {
        // If the independent watcher already confirmed authorization, this
        // promise is no longer relevant to the UI.
        if (attempt !== loginAttempt || state.status === 'connected') return;
        throw e;
      }

      if (attempt !== loginAttempt || state.status === 'connected') return;

      stopAuthWatcher();
      fs.writeFileSync(SESSION_FILE, client.session.save(), { mode: 0o600 });
      state = { status: 'connected', qr: null, needPassword: false, error: null };
      passwordResolver = null;
      await resumePersistedLoops();
    } catch (e) {
      if (attempt !== loginAttempt || state.status === 'connected') return;
      stopAuthWatcher();
      state = { status: 'idle', qr: null, needPassword: false, error: e.message };
    }
  })();
});

app.post('/api/password', panelGuard, (req, res) => {
  if (!passwordResolver) return res.status(409).json({ error: 'No Telegram 2FA request is pending.' });
  const p = String(req.body?.password || '');
  if (!p) return res.status(400).json({ error: 'Password is required.' });
  passwordResolver(p); passwordResolver = null; state.needPassword = false; res.json({ ok: true });
});
app.get('/api/status', panelGuard, (req, res) => res.json(publicState()));

app.post('/api/disconnect', panelGuard, async (req, res) => {
  loginAttempt++;
  stopAuthWatcher();

  for (const l of loops.values()) stopLoop(l);
  dialogMap = new Map();
  folderMap = new Map();
  passwordResolver = null;

  const oldClient = client;
  client = null;

  if (!oldClient) {
    if (fs.existsSync(SESSION_FILE)) fs.rmSync(SESSION_FILE, { force: true });
    state = { status: 'idle', qr: null, needPassword: false, error: null };
    return res.json({ ok: true, loggedOut: true, newSessionRequired: true });
  }

  let logoutConfirmed = false;

  try {
    // auth.LogOut revokes THIS authorization on Telegram's servers.
    // Bound it so a stalled Telegram socket can never keep the UI stuck
    // on "Disconnecting..." for minutes.
    if (oldClient.connected && state.status === 'connected') {
      const logoutPromise = oldClient.invoke(new Api.auth.LogOut({}))
        .then(() => { logoutConfirmed = true; })
        .catch(() => {});

      await Promise.race([logoutPromise, sleep(6000)]);
    }
  } finally {
    try {
      if (typeof oldClient.destroy === 'function') {
        await Promise.race([oldClient.destroy(), sleep(1500)]);
      } else {
        await Promise.race([oldClient.disconnect(), sleep(1500)]);
      }
    } catch (_) {}

    // If Telegram acknowledged logout, remove the saved authorization.
    // On a timeout/failure we still clear the local session so the next
    // connection cannot silently reuse it; Telegram may need a moment to
    // reflect the revoke if the network was unhealthy.
    if (logoutConfirmed && fs.existsSync(SESSION_FILE)) {
      try { fs.rmSync(SESSION_FILE, { force: true }); } catch (_) {}
    } else if (fs.existsSync(SESSION_FILE)) {
      // The session must never be reused after the user explicitly requested
      // Disconnect. This also guarantees the next login starts from a fresh QR.
      try { fs.rmSync(SESSION_FILE, { force: true }); } catch (_) {}
    }

    state = {
      status: 'idle',
      qr: null,
      needPassword: false,
      error: logoutConfirmed ? null : 'Telegram logout request timed out; a fresh QR will be required.'
    };
    res.json({ ok: true, loggedOut: logoutConfirmed, newSessionRequired: true });
  }
});


/* ---------------- CHATS ---------------- */
async function loadDialogs() {
  const dialogs = await client.getDialogs({ limit: 1000 });
  const map = new Map();
  for (const d of dialogs) {
    const e = d.entity; if (!e) continue;
    const id = d.id.toString();
    const type = d.isGroup ? 'group' : d.isChannel ? 'channel' : 'user';
    let canSend = true;
    if (type === 'channel' && !e.creator && !e.adminRights) canSend = false;
    if (type === 'group' && e.defaultBannedRights?.sendMessages && !e.creator && !e.adminRights) canSend = false;
    map.set(id, {
      id,
      title: d.title || d.name || 'Unknown',
      type,
      unread: d.unreadCount || 0,
      archived: !!d.archived,
      canSend,
      entity: e
    });
  }
  dialogMap = map;
  return map;
}

function peerToDialogId(peer) {
  if (!peer) return null;
  // GramJS uses marked peer IDs:
  //   user    -> 123
  //   group   -> -123
  //   channel -> -100123
  // Do not use the archive folder_id here; dialog-filter peers are
  // represented by InputPeer* objects.
  if (peer.userId != null) return String(peer.userId);
  if (peer.chatId != null) return String(-Number(peer.chatId));
  if (peer.channelId != null) return '-100' + String(peer.channelId);
  return null;
}

function folderTitle(filter) {
  const title = filter?.title;
  return typeof title === 'string' ? title : (title?.text || 'Untitled folder');
}

function folderMatchesChat(filter, chat) {
  const e = chat.entity || {};
  const type = chat.type;
  const isBot = !!e.bot;
  const isGroup = type === 'group';
  const isBroadcast = type === 'channel' && !e.megagroup;
  const isUser = type === 'user';
  const isContact = !!e.contact;

  let included = false;
  const hasCategory = !!(filter.contacts || filter.nonContacts || filter.groups || filter.broadcasts || filter.bots);
  if (filter.contacts && isUser && isContact) included = true;
  if (filter.nonContacts && isUser && !isContact) included = true;
  if (filter.groups && isGroup) included = true;
  if (filter.broadcasts && isBroadcast) included = true;
  if (filter.bots && isBot) included = true;
  if (!hasCategory) included = true;

  const includedPeers = [...(filter.includePeers || []), ...(filter.pinnedPeers || [])]
    .map(peerToDialogId).filter(Boolean);
  const excludedPeers = (filter.excludePeers || []).map(peerToDialogId).filter(Boolean);
  if (includedPeers.includes(chat.id)) included = true;
  if (excludedPeers.includes(chat.id)) included = false;

  if (filter.excludeMuted && chat.muted) included = false;
  if (filter.excludeRead && !chat.unread) included = false;
  if (filter.excludeArchived && chat.archived) included = false;
  return included;
}

async function loadFolders() {
  const result = await client.invoke(new Api.messages.GetDialogFilters());
  const filters = Array.isArray(result?.filters) ? result.filters : [];
  const map = new Map();

  // IMPORTANT:
  // Telegram "chat folders" are DialogFilter objects, not the archive
  // folder_id accepted by messages.getDialogs(). The latter is why the
  // previous implementation returned empty folders on real accounts.
  //
  // Telegram exposes the exact folder rules as:
  //   contacts / nonContacts / groups / broadcasts / bots
  //   includePeers / pinnedPeers
  //   excludePeers
  //   excludeArchived / excludeRead
  //
  // We evaluate those rules against the same dialog cache that powers the
  // normal All/Groups/Channels/Private lists. This keeps folder membership
  // faithful to the user's actual Telegram configuration.

  const chats = [...dialogMap.values()];

  for (const filter of filters) {
    if (!filter || filter.id == null || filter.className === 'DialogFilterDefault') continue;

    const id = String(filter.id);
    const includedPeerIds = new Set(
      [...(filter.includePeers || []), ...(filter.pinnedPeers || [])]
        .map(peerToDialogId)
        .filter(Boolean)
    );
    const excludedPeerIds = new Set(
      (filter.excludePeers || []).map(peerToDialogId).filter(Boolean)
    );

    const hasCategoryRule = !!(
      filter.contacts ||
      filter.nonContacts ||
      filter.groups ||
      filter.broadcasts ||
      filter.bots
    );

    const members = chats.filter(chat => {
      const e = chat.entity || {};
      const isUser = chat.type === 'user';
      const isGroup = chat.type === 'group';
      const isChannel = chat.type === 'channel';
      const isBroadcast = isChannel && !e.megagroup;
      const isBot = isUser && !!e.bot;
      const isContact = isUser && !!e.contact;

      // A DialogFilter with no category flags starts empty and is populated
      // by its explicit includePeers/pinnedPeers.
      let included = false;

      if (filter.contacts && isContact) included = true;
      if (filter.nonContacts && isUser && !isContact) included = true;
      if (filter.groups && isGroup) included = true;
      if (filter.broadcasts && isBroadcast) included = true;
      if (filter.bots && isBot) included = true;

      // Explicitly included/pinned peers are part of the folder regardless
      // of whether a category rule is also present.
      if (includedPeerIds.has(chat.id)) included = true;

      // Explicit exclusions always win.
      if (excludedPeerIds.has(chat.id)) included = false;

      // Folder rules can exclude archived/read dialogs. GramJS exposes
      // archived state on Dialog; unread is already cached in this app.
      if (filter.excludeArchived && chat.archived) included = false;
      if (filter.excludeRead && !chat.unread) included = false;

      // excludeMuted requires notification settings per peer. We deliberately
      // do not guess here; all actual membership-defining rules above remain
      // exact, while avoiding hundreds of extra API calls during every sync.
      // Telegram's other folder criteria and explicit peer lists are handled
      // server-side in the official clients and locally here from the filter.

      return included;
    });

    map.set(id, {
      id,
      title: folderTitle(filter),
      count: members.length,
      groups: members.filter(c => c.type === 'group').length,
      channels: members.filter(c => c.type === 'channel').length,
      chats: members.map(({ id, title, type, unread, canSend }) => ({
        id, title, type, unread, canSend
      }))
    });
  }

  folderMap = map;
  return map;
}

async function getChat(id) { if (!dialogMap.has(id)) await loadDialogs(); return dialogMap.get(id); }
app.get('/api/chats', clientGuard, async (req, res) => {
  try {
    if (req.query.refresh === '1' || dialogMap.size === 0) await loadDialogs();
    await loadFolders();
    res.json({ chats: [...dialogMap.values()].map(({ id, title, type, unread, canSend }) => ({ id, title, type, unread, canSend })) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/folders', clientGuard, async (req, res) => {
  try {
    if (dialogMap.size === 0) await loadDialogs();
    await loadFolders();
    res.json({ folders: [...folderMap.values()] });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/messages', clientGuard, async (req, res) => {
  try {
    const chat = await getChat(String(req.query.chatId)); if (!chat) return res.status(404).json({ error: 'Chat not found.' });
    const limit = Math.min(parseInt(req.query.limit, 10) || 40, 100);
    const msgs = await client.getMessages(chat.entity, { limit });
    res.json({ messages: msgs.map((m) => ({ id: m.id, text: m.message || (m.media ? '[media]' : ''), date: m.date, out: !!m.out, from: m.out ? 'Me' : (m.sender && (m.sender.firstName || m.sender.title)) || '' })).reverse() });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/me', clientGuard, async (req, res) => { try { const me = await client.getMe(); res.json({ name: me.firstName || me.username || 'Telegram user', username: me.username, phone: me.phone }); } catch (e) { res.status(500).json({ error: e.message }); } });

/* ---------------- FORMATTING ---------------- */
function buildEntities(text, list) {
  const out = []; if (!Array.isArray(list)) return out;
  for (const e of list) {
    const offset = e.offset | 0, length = e.length | 0;
    if (length <= 0 || offset < 0 || offset + length > text.length) continue;
    const p = { offset, length };
    switch (e.type) {
      case 'bold': out.push(new Api.MessageEntityBold(p)); break;
      case 'italic': out.push(new Api.MessageEntityItalic(p)); break;
      case 'underline': out.push(new Api.MessageEntityUnderline(p)); break;
      case 'strike': out.push(new Api.MessageEntityStrike(p)); break;
      case 'code': out.push(new Api.MessageEntityCode(p)); break;
      case 'pre': out.push(new Api.MessageEntityPre({ ...p, language: '' })); break;
      case 'spoiler': out.push(new Api.MessageEntitySpoiler(p)); break;
      case 'blockquote': if (Api.MessageEntityBlockquote) out.push(new Api.MessageEntityBlockquote(p)); break;
      case 'url': if (e.url) out.push(new Api.MessageEntityTextUrl({ ...p, url: String(e.url).slice(0, 2048) })); break;
    }
  }
  return out;
}
async function safeSend(chat, text, entities) {
  try {
    const ents = buildEntities(text, entities); const params = { message: text }; if (ents.length) params.formattingEntities = ents;
    await client.sendMessage(chat.entity, params); return { ok: true };
  } catch (e) {
    const msg = e.errorMessage || e.message || String(e); const slow = /^SLOWMODE_WAIT/.test(msg); const flood = !slow && /FLOOD/.test(msg);
    return { ok: false, error: msg, wait: e.seconds || null, slow, flood };
  }
}
function addHistory(entry) {
  history.unshift({ id: nextHistoryId++, at: Date.now(), ...entry }); history = history.slice(0, MAX_HISTORY); saveData();
}

/* ---------------- INDIVIDUAL SEND ---------------- */
app.post('/api/send', clientGuard, async (req, res) => {
  const chatId = String(req.body?.chatId || ''); const text = safeText(req.body?.text); const entities = Array.isArray(req.body?.entities) ? req.body.entities : [];
  const bad = validateText(text); if (bad) return res.status(400).json({ error: bad });
  const chat = await getChat(chatId); if (!chat) return res.status(404).json({ error: 'Chat not found.' });
  if (!chat.canSend) return res.status(403).json({ error: 'You do not have permission to send messages to this chat.' });
  const r = await safeSend(chat, text, entities);
  addHistory({ kind: 'individual', chatId, chatTitle: chat.title, text, entities, status: r.ok ? 'sent' : 'failed', error: r.ok ? null : r.error });
  if (!r.ok) return res.status(400).json({ error: r.error + (r.wait ? ` (wait ${r.wait}s)` : '') });
  res.json({ ok: true });
});

/* ---------------- TEMPLATES ---------------- */
app.get('/api/templates', panelGuard, (req, res) => res.json({ templates }));
app.post('/api/templates', panelGuard, (req, res) => {
  const name = safeText(req.body?.name, 120).trim(); const text = safeText(req.body?.text); const entities = Array.isArray(req.body?.entities) ? req.body.entities : [];
  const bad = validateText(text); if (!name) return res.status(400).json({ error: 'Template name is required.' }); if (bad) return res.status(400).json({ error: bad });
  if (templates.length >= MAX_TEMPLATES) return res.status(400).json({ error: 'Template limit reached.' });
  const t = { id: crypto.randomUUID(), name, text, entities, createdAt: Date.now(), updatedAt: Date.now() }; templates.unshift(t); saveData(); res.json({ ok: true, template: t });
});
app.put('/api/templates/:id', panelGuard, (req, res) => {
  const t = templates.find((x) => x.id === req.params.id); if (!t) return res.status(404).json({ error: 'Template not found.' });
  const name = safeText(req.body?.name, 120).trim(); const text = safeText(req.body?.text); const bad = validateText(text); if (!name || bad) return res.status(400).json({ error: !name ? 'Template name is required.' : bad });
  t.name = name; t.text = text; t.entities = Array.isArray(req.body?.entities) ? req.body.entities : []; t.updatedAt = Date.now(); saveData(); res.json({ ok: true, template: t });
});
app.delete('/api/templates/:id', panelGuard, (req, res) => { const before = templates.length; templates = templates.filter((x) => x.id !== req.params.id); saveData(); res.json({ ok: true, deleted: before !== templates.length }); });

/* ---------------- HISTORY / STATS ---------------- */
app.get('/api/history', panelGuard, (req, res) => {
  const limit = Math.min(parseInt(req.query.limit, 10) || 100, 500); const status = req.query.status;
  const rows = history.filter((h) => !status || h.status === status).slice(0, limit);
  res.json({ history: rows });
});
app.post('/api/history/:id/retry', clientGuard, async (req, res) => {
  const h = history.find((x) => x.id === parseInt(req.params.id, 10)); if (!h) return res.status(404).json({ error: 'History item not found.' });
  const chat = await getChat(h.chatId); if (!chat) return res.status(404).json({ error: 'Chat not found.' });
  if (!chat.canSend) return res.status(403).json({ error: 'You do not have permission to send to this chat.' });
  const r = await safeSend(chat, h.text, h.entities || []);
  addHistory({ kind: 'retry', chatId: h.chatId, chatTitle: chat.title, text: h.text, entities: h.entities || [], status: r.ok ? 'sent' : 'failed', error: r.ok ? null : r.error });
  if (!r.ok) return res.status(400).json({ error: r.error }); res.json({ ok: true });
});
app.get('/api/stats', panelGuard, (req, res) => {
  const today = new Date(); const start = new Date(today.getFullYear(), today.getMonth(), today.getDate()).getTime();
  const day = history.filter((h) => h.at >= start); const sent = history.filter((h) => h.status === 'sent').length; const failed = history.filter((h) => h.status === 'failed').length;
  res.json({ today: day.length, sent, failed, activeJobs: [...loops.values()].filter((l) => l.running).length, totalJobs: loops.size, templates: templates.length });
});

/* ---------------- AUTO SENDER ---------------- */
const STOP_ERRORS = /WRITE_FORBIDDEN|BANNED|ADMIN_REQUIRED|PEER_ID_INVALID|USER_DEACTIVATED|CHAT_RESTRICTED|CHANNEL_PRIVATE|USER_BLOCKED/;
function info(l) { return { id:l.id, text:l.text, intervalSec:l.intervalSec, gapSec:l.gapSec, maxRounds:l.maxRounds, round:l.round, sent:l.sent, running:l.running, paused:l.paused, lastSent:l.lastSent, lastError:l.lastError, nextAt:l.nextAt, startAt:l.startAt, createdAt:l.createdAt, groups:l.groups.map((g)=>({chatId:g.chatId,title:g.title,sent:g.sent,error:g.error,disabled:g.disabled})) }; }
async function waitFor(l, ms) { const end=Date.now()+ms; while(l.running && !l.paused && Date.now()<end) await sleep(Math.min(500, end-Date.now())); }
async function run(l, token) {
  try {
    if (l.startAt && l.startAt > Date.now()) { l.nextAt=l.startAt; await waitFor(l, Math.max(0,l.startAt-Date.now())); l.startAt=null; }
    while (l.running && !l.paused && l.token===token) {
      const roundStart=Date.now(); l.round++; let floodDelay=0;
      for (const g of l.groups) {
        if (!l.running || l.paused || l.token!==token) break; if (g.disabled) continue;
        const chat=await getChat(g.chatId); if(!chat){g.error='Chat not found';g.disabled=true;continue;} if(!chat.canSend){g.error='Sending permission unavailable';g.disabled=true;continue;}
        let r=await safeSend(chat,l.text,l.entities);
        if(r.ok){g.sent++;g.error=null;l.sent++;l.lastSent=Date.now();l.lastError=null;addHistory({kind:'auto',jobId:l.id,chatId:g.chatId,chatTitle:g.title,text:l.text,entities:l.entities,status:'sent',error:null});}
        else if(r.slow){g.error=`Slow mode: ${r.wait||'?'}s`;addHistory({kind:'auto',jobId:l.id,chatId:g.chatId,chatTitle:g.title,text:l.text,entities:l.entities,status:'failed',error:r.error});}
        else if(r.flood){g.error=`Flood wait: ${r.wait||'?'}s`;l.lastError=`Telegram requested a ${r.wait||'?'}s cooldown.`;addHistory({kind:'auto',jobId:l.id,chatId:g.chatId,chatTitle:g.title,text:l.text,entities:l.entities,status:'failed',error:r.error});floodDelay=Math.max(floodDelay,((r.wait||60)+2)*1000);break;}
        else {g.error=r.error;addHistory({kind:'auto',jobId:l.id,chatId:g.chatId,chatTitle:g.title,text:l.text,entities:l.entities,status:'failed',error:r.error});if(STOP_ERRORS.test(r.error))g.disabled=true;}
        await waitFor(l,l.gapSec*1000);
      }
      if(!l.running||l.paused)break;
      if(l.groups.every((g)=>g.disabled)){l.lastError='All selected chats are unavailable for sending.';break;}
      if(l.maxRounds && l.round>=l.maxRounds){l.lastError='Maximum rounds completed.';break;}
      const elapsed=Date.now()-roundStart; const delay=Math.max(floodDelay,l.intervalSec*1000-elapsed,5000);l.nextAt=Date.now()+delay;await waitFor(l,delay);l.nextAt=null;
    }
  } catch(e){l.lastError=e.message;}
  if(l.token===token){l.running=false;l.nextAt=null;l.paused=false;saveData();}
}
function startLoop(l) { if(l.running)return; l.running=true;l.paused=false;l.lastError=null;l.token++;saveData();run(l,l.token); }
function pauseLoop(l) { l.paused=true;l.running=false;l.token++;l.nextAt=null;saveData(); }
function stopLoop(l) { l.paused=false;l.running=false;l.token++;l.nextAt=null;saveData(); }

app.get('/api/loops', panelGuard, (req,res)=>res.json({loops:[...loops.values()].map(info)}));
app.post('/api/loops', clientGuard, async (req,res)=>{
  const {chatIds,text,entities,intervalSec,gapSec,maxRounds,startAt}=req.body; const bad=validateText(text); if(bad)return res.status(400).json({error:bad});
  if(!Array.isArray(chatIds)||!chatIds.length)return res.status(400).json({error:'Select at least one chat.'});
  const groups=[]; for(const id of [...new Set(chatIds.map(String))]){const chat=await getChat(id);if(chat&&chat.canSend)groups.push({chatId:id,title:chat.title,sent:0,error:null,disabled:false});}
  if(!groups.length)return res.status(400).json({error:'No selected chat is available for sending.'});
  const interval=Math.max(10,Math.min(86400,parseInt(intervalSec,10)||60)); const gap=Math.max(1,Math.min(3600,parseInt(gapSec,10)||3)); const max=Math.max(0,Math.min(10000,parseInt(maxRounds,10)||0));
  const parsedStart=startAt?Date.parse(startAt):Date.now(); if(Number.isNaN(parsedStart))return res.status(400).json({error:'Invalid start time.'});
  const l={id:loopSeq++,text:String(text),entities:Array.isArray(entities)?entities:[],groups,intervalSec:interval,gapSec:gap,maxRounds:max,round:0,sent:0,running:false,paused:false,token:0,lastSent:null,lastError:null,nextAt:parsedStart>Date.now()?parsedStart:null,startAt:parsedStart>Date.now()?parsedStart:null,createdAt:Date.now(),updatedAt:Date.now()};
  loops.set(l.id,l); saveData(); if(parsedStart<=Date.now())startLoop(l); res.json({ok:true,loop:info(l)});
});
app.post('/api/loops/:id/pause', panelGuard,(req,res)=>{const l=loops.get(parseInt(req.params.id,10));if(!l)return res.status(404).json({error:'Job not found.'});pauseLoop(l);res.json({ok:true});});
app.post('/api/loops/:id/start', clientGuard,(req,res)=>{const l=loops.get(parseInt(req.params.id,10));if(!l)return res.status(404).json({error:'Job not found.'});l.groups.forEach((g)=>{if(g.disabled){g.disabled=false;g.error=null;}});startLoop(l);res.json({ok:true});});
app.post('/api/loops/:id/stop', panelGuard,(req,res)=>{const l=loops.get(parseInt(req.params.id,10));if(!l)return res.status(404).json({error:'Job not found.'});stopLoop(l);res.json({ok:true});});
app.delete('/api/loops/:id',panelGuard,(req,res)=>{const l=loops.get(parseInt(req.params.id,10));if(!l)return res.json({ok:true});stopLoop(l);loops.delete(l.id);saveData();res.json({ok:true});});

function restoreData(){
  const d=readData(); templates=Array.isArray(d.templates)?d.templates:[];history=Array.isArray(d.history)?d.history:[];nextHistoryId=Number(d.nextHistoryId)||1;loopSeq=Number(d.loopSeq)||1;
  if(Array.isArray(d.loops)) for(const raw of d.loops){const l={...raw,running:false,paused:false,token:0,nextAt:null};loops.set(l.id,l);loopSeq=Math.max(loopSeq,Number(l.id)+1);}
}
async function resumePersistedLoops(){
  if(state.status!=='connected')return; if(!loops.size)return;
  await loadDialogs().catch(()=>{});
  for(const l of loops.values()){
    const valid=[];for(const g of l.groups){const c=await getChat(g.chatId).catch(()=>null);if(c&&c.canSend){g.title=c.title;valid.push(g);}else{g.disabled=true;g.error='Chat unavailable or sending permission missing.';}}
    if(!valid.length){l.lastError='No valid chats remain.';continue;}
    const due=l.startAt?Date.parse(l.startAt):Date.now(); if(!Number.isFinite(due)||due<=Date.now())startLoop(l); else {l.nextAt=due;setTimeout(()=>{if(!l.running&&!l.paused)startLoop(l);},Math.max(0,due-Date.now()));}
  }
  saveData();
}

restoreData();
init().then(()=>app.listen(PORT,()=>console.log('Telegram Control Center running on http://localhost:'+PORT))).catch((e)=>{console.error('Startup failed:',e);process.exitCode=1;});
