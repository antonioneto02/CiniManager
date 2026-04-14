'use strict';
require('dotenv').config();
const express       = require('express');
const pm2           = require('pm2');
const path          = require('path');
const fs            = require('fs');
const axios         = require('axios');
const session       = require('express-session');
const cookieParser  = require('cookie-parser');
const { execSync, execFileSync, execFile } = require('child_process');
const crypto        = require('crypto');
const sql           = require('mssql');
const app  = express();
const PORT = parseInt(process.env.DASHBOARD_PORT) || 9999;

const PROTHEUS_SERVER = process.env.PROTHEUS_SERVER || 'protheus.cini.com.br';
const SESSION_SECRET = process.env.SESSION_SECRET || 'cini_manager_secret_2026';
const ALLOWED_USER_BY_ID = {
  '000460': 'antonio.neto',
  '000005': 'nerias',
};

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use('/css', express.static(path.join(__dirname, 'public', 'css')));
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 8 * 60 * 60 * 1000 },
}));
app.get('/Cini.png', (req, res) => res.sendFile(path.join(__dirname, 'Cini.png')));

function normalizeUserId(v) {
  return String(v || '').trim().padStart(6, '0');
}

function normalizeUsername(v) {
  return String(v || '').trim().toLowerCase();
}

function isAllowedUserId(userId) {
  return !!ALLOWED_USER_BY_ID[normalizeUserId(userId)];
}

function isAllowedUserPair(userId, username) {
  const id = normalizeUserId(userId);
  const expected = ALLOWED_USER_BY_ID[id];
  if (!expected) return false;
  return normalizeUsername(username) === normalizeUsername(expected);
}

function clearAuthCookies(res) {
  res.clearCookie('token', { httpOnly: true, secure: false, sameSite: 'lax' });
  res.clearCookie('refresh_token', { httpOnly: true, secure: false, sameSite: 'lax' });
  res.clearCookie('username', { httpOnly: true, secure: false, sameSite: 'lax' });
}

async function fetchUserFromToken(accessToken) {
  const userIdResp = await axios.get(
    `http://${PROTHEUS_SERVER}:9001/rest/users/getuserid`,
    { headers: { Authorization: `Bearer ${accessToken}` } }
  );
  const userID = normalizeUserId(userIdResp?.data?.userID);
  if (!userID) throw new Error('user_id_not_found');

  let profile = {};
  try {
    const userResp = await axios.get(
      `http://${PROTHEUS_SERVER}:9001/rest/users/${userID}`,
      { headers: { Authorization: `Bearer ${accessToken}` } }
    );
    profile = userResp?.data || {};
  } catch {}

  const displayName = String(profile.name || profile.fullName || profile.displayName || ALLOWED_USER_BY_ID[userID] || userID);
  return { userID, displayName };
}

async function refreshToken(refreshToken, res) {
  const response = await axios.post(
    `http://${PROTHEUS_SERVER}:9001/rest/api/oauth2/v1/token`,
    null,
    {
      params: {
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
      },
    }
  );

  const accessToken = response?.data?.access_token;
  const newRefreshToken = response?.data?.refresh_token;
  if (!accessToken || !newRefreshToken) throw new Error('refresh_failed');

  res.cookie('token', accessToken, {
    httpOnly: true,
    secure: false,
    sameSite: 'lax',
    maxAge: 3600000,
  });
  res.cookie('refresh_token', newRefreshToken, {
    httpOnly: true,
    secure: false,
    sameSite: 'lax',
    maxAge: 43200000,
  });
  return accessToken;
}

function denyAuth(req, res) {
  if (req.path.startsWith('/api/')) {
    return res.status(401).json({ error: 'Não autenticado' });
  }
  return res.redirect('/loginPage');
}

async function ensureAuth(req, res, next) {
  if (
    req.session &&
    req.session.userID &&
    req.session.username &&
    isAllowedUserPair(req.session.userID, req.session.username)
  ) {
    req.session.lastActivity = Date.now();
    return next();
  }

  let token = req.cookies && req.cookies.token;
  const refresh = req.cookies && req.cookies.refresh_token;
  if (!token && refresh) {
    try {
      token = await refreshToken(refresh, res);
    } catch {
      clearAuthCookies(res);
      if (req.session) req.session.destroy(() => {});
      return denyAuth(req, res);
    }
  }

  if (!token) return denyAuth(req, res);

  try {
    const { userID, displayName } = await fetchUserFromToken(token);
    if (!isAllowedUserId(userID)) {
      clearAuthCookies(res);
      if (req.session) req.session.destroy(() => {});
      if (req.path.startsWith('/api/')) {
        return res.status(403).json({ error: 'Usuário sem permissão no Cini Manager' });
      }
      return res.redirect('/loginPage?error=not_allowed');
    }

    req.session.userID = userID;
    req.session.username = ALLOWED_USER_BY_ID[userID];
    req.session.displayName = displayName;
    req.session.lastActivity = Date.now();
    return next();
  } catch {
    clearAuthCookies(res);
    if (req.session) req.session.destroy(() => {});
    return denyAuth(req, res);
  }
}

app.get('/loginPage', (req, res) => {
  if (
    req.session &&
    req.session.userID &&
    req.session.username &&
    isAllowedUserPair(req.session.userID, req.session.username)
  ) {
    return res.redirect('/');
  }
  return res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.post('/login', async (req, res) => {
  const username = normalizeUsername(req.body.username);
  const password = req.body.password || '';
  if (!username || !password) {
    return res.status(400).json({ error: 'Preencha usuário e senha' });
  }

  try {
    const tokenResp = await axios.post(
      `http://${PROTHEUS_SERVER}:9001/rest/api/oauth2/v1/token`,
      null,
      {
        params: {
          grant_type: 'password',
          username,
          password,
        },
      }
    );
    const accessToken = tokenResp?.data?.access_token;
    const refreshTokenValue = tokenResp?.data?.refresh_token;
    if (!accessToken || !refreshTokenValue) {
      return res.status(401).json({ error: 'Credenciais inválidas' });
    }

    const { userID, displayName } = await fetchUserFromToken(accessToken);
    const expectedUsername = ALLOWED_USER_BY_ID[userID];
    if (!expectedUsername || username !== expectedUsername) {
      clearAuthCookies(res);
      if (req.session) req.session.destroy(() => {});
      return res.status(403).json({ error: 'Acesso negado ao Cini Manager' });
    }

    res.cookie('token', accessToken, {
      httpOnly: true,
      secure: false,
      sameSite: 'lax',
      maxAge: 3600000,
    });
    res.cookie('refresh_token', refreshTokenValue, {
      httpOnly: true,
      secure: false,
      sameSite: 'lax',
      maxAge: 43200000,
    });
    res.cookie('username', username, {
      httpOnly: true,
      secure: false,
      sameSite: 'lax',
      maxAge: 43200000,
    });

    req.session.userID = userID;
    req.session.username = username;
    req.session.displayName = displayName;
    req.session.lastActivity = Date.now();

    return res.json({ ok: true });
  } catch {
    clearAuthCookies(res);
    if (req.session) req.session.destroy(() => {});
    return res.status(401).json({ error: 'Credenciais inválidas' });
  }
});

app.get('/logout', (req, res) => {
  clearAuthCookies(res);
  if (req.session) req.session.destroy(() => {});
  return res.redirect('/loginPage?logout=true');
});

app.use((req, res, next) => {
  if (req.path === '/loginPage' || req.path === '/login' || req.path === '/logout' || req.path === '/Cini.png') {
    return next();
  }
  return ensureAuth(req, res, next);
});

app.use(express.static(path.join(__dirname, 'public')));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

const APP_REGISTRY = {
  'api-weduu':       'C:/Projetos/API_Weduu',
  'erp-cini':        'E:/Projetos/Gestao_Portaria/erp_cini',
  'wf-cini':         'E:/Projetos/WF_Cini/wf_cini',
  'central-tarefas': 'E:/Projetos/Central_Tarefas',
  'hub-cini':        'E:/Projetos/Hub_Cini',
  'cini-pricing':    'E:/Projetos/Cini-Pricing',
  'api-sicredi':     'E:/Projetos/API_Sicredi',
  'notificador-pix': 'C:/Projetos/Confirmacao_Pix/NotificadorPIX',
  'log-watcher':     'E:/Projetos/CiniManager',
  'cini-dashboard':  'E:/Projetos/CiniManager/dashboard',
  'whatsapp-bot':         'E:/Projetos/Central-Notificacoes/whatsapp-bot',
  'webhook-whatsapp':     'C:/Projetos/WebhookWhatsAppNode',
  'client-baixas-pix':    'C:/Projetos/ClientBaixasPIX',
  'portal-consultas':     'C:/Projetos/PortalConsultasCini',
  'portal-streamlit':     'C:/Projetos/PortalConsultasStreamlit',
  'gerenciador-cargas':   'C:/Projetos/gerenciador-cargas',
  'whatsapp-motoristas':  'E:/Projetos/Central-Notificacoes/WhatsAppMotoristas',
  'whatsapp-webnode':     'E:/Projetos/Central-Notificacoes/WhatsAppWebNode',
  'central-notificacoes': 'E:/Projetos/Central-Notificacoes/CentralNotificacoes',
};

const DEPLOY_EXCLUDE    = new Set(['log-watcher']);
const STAGED_DEPLOY_APPS = new Set(['cini-dashboard']); 
const AUTOPOLL_FILE = path.join(__dirname, '.autopoll.json');
const CARD_ORDER_FILE = path.join(__dirname, '.card-order.json');
const DISPLAY_NAMES = {
  'erp-cini': 'Gestão Portaria',
  'cini-dashboard': 'Cini Manager',
  'client-baixas-pix': 'Baixas PIX',
  'central-notificacoes': 'Central Notificações',
  'wf-cini': 'Workflow Cini',
  'api-weduu': 'API Weduu',
  'central-tarefas': 'Central de Tarefas',
  'hub-cini': 'HUB Cini',
  'cini-pricing': 'Pricing Cini',
  'api-sicredi': 'API Sicredi',
  'notificador-pix': 'Notificações PIX',
  'whatsapp-bot': 'BOT WhatsApp',
  'portal-consultas': 'Portal de Consultas',
  'portal-streamlit': 'Portal Stremalit',
  'gerenciador-cargas': 'Portal de Cargas',
  'whatsapp-motoristas': 'Tracking',
  'whatsapp-webnode': 'Cini Notifica e WB Sicredi',
};

function appLabel(name) {
  return DISPLAY_NAMES[name] || name;
}

function loadAutoPoll() {
  try {
    if (fs.existsSync(AUTOPOLL_FILE))
      return JSON.parse(fs.readFileSync(AUTOPOLL_FILE, 'utf8'));
  } catch {}
  return { enabled: true, intervalMin: 2, apps: {} };
}

function loadCardOrder() {
  try {
    if (fs.existsSync(CARD_ORDER_FILE)) {
      const parsed = JSON.parse(fs.readFileSync(CARD_ORDER_FILE, 'utf8'));
      if (Array.isArray(parsed.apps)) return parsed.apps;
    }
  } catch {}
  return [];
}

function saveAutoPoll() {
  try { fs.writeFileSync(AUTOPOLL_FILE, JSON.stringify(autoPollCfg, null, 2), 'utf8'); } catch {}
}

function saveCardOrder() {
  try { fs.writeFileSync(CARD_ORDER_FILE, JSON.stringify({ apps: cardOrder }, null, 2), 'utf8'); } catch {}
}

let autoPollCfg = loadAutoPoll();
let cardOrder = loadCardOrder();

const WPP_DEST = '554188529918';
const DB_CFG   = {
  server:   'localhost',
  database: 'dw',
  user:     'cini.tracking',
  password: 'k00b82f6j9TO6alM',
  options:  { trustServerCertificate: true, encrypt: false },
  pool:     { max: 3, min: 0, idleTimeoutMillis: 10000 },
};

const GROUPS_DB_CFG = {
  server: process.env.DB_SERVER_ERP || 'localhost',
  database: process.env.DB_DATABASE_DW || 'dw',
  user: process.env.DB_USER_ERP || 'gestao.portaria',
  password: process.env.DB_PASSWORD_ERP || '0wd10ARpf522tQzM',
  options: { trustServerCertificate: true, encrypt: false },
  pool: { max: 2, min: 0, idleTimeoutMillis: 10000 },
};

let _pool = null;
let _poolPromise = null;
let _groupsPool = null;
let _groupsPoolPromise = null;

async function getPool() {
  if (_pool) return _pool;
  if (!_poolPromise) {
    _poolPromise = new sql.ConnectionPool(DB_CFG).connect()
      .then(pool => {
        _pool = pool;
        _poolPromise = null;
        pool.on('error', () => { _pool = null; });
        return pool;
      })
      .catch(err => {
        _poolPromise = null;
        throw err;
      });
  }
  return _poolPromise;
}

async function getGroupsPool() {
  if (_groupsPool) return _groupsPool;
  if (!_groupsPoolPromise) {
    _groupsPoolPromise = new sql.ConnectionPool(GROUPS_DB_CFG).connect()
      .then(pool => {
        _groupsPool = pool;
        _groupsPoolPromise = null;
        pool.on('error', () => { _groupsPool = null; });
        return pool;
      })
      .catch(err => {
        _groupsPoolPromise = null;
        throw err;
      });
  }
  return _groupsPoolPromise;
}

async function listServiceGroups() {
  const p = await getGroupsPool();
  const groupsRs = await p.request().query(`
    SELECT ID_GRUPO, NOME_GRUPO
    FROM dbo.CINI_MANAGER_GRUPOS
    WHERE ATIVO = 1
    ORDER BY NOME_GRUPO
  `);
  const appsRs = await p.request().query(`
    SELECT ID_GRUPO, APP_NAME, ORDEM
    FROM dbo.CINI_MANAGER_GRUPOS_APPS
    ORDER BY ID_GRUPO, ORDEM, APP_NAME
  `);

  const byGroup = new Map();
  for (const g of groupsRs.recordset || []) {
    byGroup.set(Number(g.ID_GRUPO), {
      id: Number(g.ID_GRUPO),
      name: String(g.NOME_GRUPO || '').trim(),
      apps: [],
    });
  }

  for (const row of appsRs.recordset || []) {
    const group = byGroup.get(Number(row.ID_GRUPO));
    if (!group) continue;
    group.apps.push(String(row.APP_NAME || '').trim());
  }

  return Array.from(byGroup.values());
}

async function createServiceGroup(name, apps) {
  const cleanName = String(name || '').trim();
  const validApps = Object.keys(APP_REGISTRY).filter(x => !DEPLOY_EXCLUDE.has(x));
  const selectedApps = [...new Set((Array.isArray(apps) ? apps : []).map(a => String(a || '').trim()).filter(a => validApps.includes(a)))];

  if (!cleanName) throw new Error('Informe o nome do grupo');
  if (cleanName.length > 120) throw new Error('Nome do grupo muito longo (máx 120)');
  if (!selectedApps.length) throw new Error('Selecione ao menos um serviço para o grupo');

  const p = await getGroupsPool();
  const tx = new sql.Transaction(p);
  await tx.begin();
  try {
    const checkReq = new sql.Request(tx);
    checkReq.input('nome', sql.NVarChar(120), cleanName);
    const exists = await checkReq.query(`
      SELECT TOP 1 ID_GRUPO
      FROM dbo.CINI_MANAGER_GRUPOS
      WHERE UPPER(NOME_GRUPO) = UPPER(@nome)
        AND ATIVO = 1
    `);
    if ((exists.recordset || []).length) {
      throw new Error('Já existe um grupo com este nome');
    }

    const insReq = new sql.Request(tx);
    insReq.input('nome', sql.NVarChar(120), cleanName);
    const ins = await insReq.query(`
      INSERT INTO dbo.CINI_MANAGER_GRUPOS (NOME_GRUPO, ATIVO, DTINC)
      OUTPUT INSERTED.ID_GRUPO
      VALUES (@nome, 1, GETDATE())
    `);
    const groupId = Number(ins.recordset[0].ID_GRUPO);

    for (let i = 0; i < selectedApps.length; i++) {
      const appName = selectedApps[i];
      const appReq = new sql.Request(tx);
      appReq.input('idGrupo', sql.Int, groupId);
      appReq.input('appName', sql.NVarChar(120), appName);
      appReq.input('ordem', sql.Int, i + 1);
      await appReq.query(`
        INSERT INTO dbo.CINI_MANAGER_GRUPOS_APPS (ID_GRUPO, APP_NAME, ORDEM, DTINC)
        VALUES (@idGrupo, @appName, @ordem, GETDATE())
      `);
    }

    await tx.commit();
    return { id: groupId, name: cleanName, apps: selectedApps };
  } catch (err) {
    try { await tx.rollback(); } catch {}
    throw err;
  }
}

async function deleteServiceGroup(groupId) {
  const id = Number(groupId);
  if (!Number.isFinite(id) || id <= 0) throw new Error('Grupo inválido');

  const p = await getGroupsPool();
  const tx = new sql.Transaction(p);
  await tx.begin();
  try {
    const checkReq = new sql.Request(tx);
    checkReq.input('idGrupo', sql.Int, id);
    const check = await checkReq.query(`
      SELECT TOP 1 ID_GRUPO, NOME_GRUPO
      FROM dbo.CINI_MANAGER_GRUPOS
      WHERE ID_GRUPO = @idGrupo
        AND ATIVO = 1
    `);
    if (!(check.recordset || []).length) {
      throw new Error('Grupo não encontrado');
    }
    const groupName = String(check.recordset[0].NOME_GRUPO || '').trim();

    const delAppsReq = new sql.Request(tx);
    delAppsReq.input('idGrupo', sql.Int, id);
    await delAppsReq.query(`
      DELETE FROM dbo.CINI_MANAGER_GRUPOS_APPS
      WHERE ID_GRUPO = @idGrupo
    `);

    const delGroupReq = new sql.Request(tx);
    delGroupReq.input('idGrupo', sql.Int, id);
    await delGroupReq.query(`
      UPDATE dbo.CINI_MANAGER_GRUPOS
      SET ATIVO = 0
      WHERE ID_GRUPO = @idGrupo
    `);

    await tx.commit();
    return { id, name: groupName };
  } catch (err) {
    try { await tx.rollback(); } catch {}
    throw err;
  }
}

async function sendWhatsApp(msg) {
  try {
    const p = await getPool();
    await p.request()
      .input('dest', sql.NVarChar(50),   WPP_DEST)
      .input('msg',  sql.NVarChar(4000), msg)
      .query(`INSERT INTO [dbo].[FATO_FILA_NOTIFICACOES]
                (TIPO_MENSAGEM, DESTINATARIO, MENSAGEM, STATUS, TENTATIVAS, DTINC)
              VALUES ('texto', @dest, @msg, 'PENDENTE', 0, GETDATE())`);
  } catch (e) {
    console.error('[wpp] Falha:', e.message);
    _pool = null;
  }
}

function trimText(text, max = 500) {
  const clean = String(text || '').replace(/\s+/g, ' ').trim();
  return clean.length > max ? clean.slice(0, max - 1) + '…' : clean;
}

async function notifyWhatsApp(title, lines = []) {
  const body = lines.filter(Boolean).join('\n');
  const msg = `${title}\n📅 ${now()}\n${'━'.repeat(25)}\n\n${body}`;
  await sendWhatsApp(msg);
}

const runtimeAlerts = new Map();
const acknowledgedAlertAt = new Map();
const logAlertThrottle = new Map();
const gitAlertThrottle = new Map();
const APP_ERROR_DUP_WINDOW_MS = 1000;
const GIT_ALERT_DUP_WINDOW_MS = 1000;
const PM2_EVENT_DUP_WINDOW_MS = 1000;
const ALERT_VISIBLE_MS = 6 * 60 * 60 * 1000;
const LOG_ERROR_PATTERNS = [
  /(^|\b)(error|exception|fatal|traceback|unhandled|failed|failure|critical|panic)(\b|:)/i,
  /ECONN|EADDR|ENOENT|ETIMEDOUT|REFUSED|timeout/i,
  /cannot\s|invalid\s|not found|denied|unauthorized|forbidden/i,
  /\bHTTP\/1\.[01]"\s[45]\d\d\b/i,
  /\bstatus\s*[=:]\s*[45]\d\d\b/i,
  /\b(?:sql|database|db)\b.*\b(error|failed|exception|timeout)\b/i,
];
const LOG_ERROR_IGNORE_PATTERNS = [
  /0 errors?/i,
  /without errors?/i,
  /deprecationwarning/i,
  /source map error/i,
  /\bINFO\b/i,
  /\bDEBUG\b/i,
  /\bHTTP\/1\.[01]"\s2\d\d\b/i,
  /Starting new HTTP connection/i,
  /Starting new HTTPS connection/i,
  /chamado com sucesso/i,
  /conclu[ií]d[ao] com sucesso/i,
  /registrad[ao] com sucesso/i,
  /dados recebidos da api/i,
  /processando /i,
  /aguardando \d+s/i,
  /pagina(?:ç|c)[aã]o/i,
  /connect\.session\(\)\s*memorystore\s*is not/i,
  /not\s+designed\s+for\s+a\s+production\s+environment/i,
  /will\s+leak\s+memory/i,
  /will\s+not\s+scale\s+past\s+a\s+single\s+process/i,
];

function rememberRuntimeAlert(appName, type, reason) {
  runtimeAlerts.set(appName, { type, reason: trimText(reason, 220), ts: Date.now() });
}

function getRuntimeAlert(appName) {
  const alert = runtimeAlerts.get(appName);
  if (!alert) return null;
  if (Date.now() - alert.ts > ALERT_VISIBLE_MS) {
    runtimeAlerts.delete(appName);
    return null;
  }
  return alert;
}

function normalizeErrorSignature(text) {
  return String(text || '')
    .toLowerCase()
    .replace(/[0-9a-f]{7,}/g, '#')
    .replace(/\d+/g, '#')
    .replace(/https?:\/\/\S+/g, 'url')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 180);
}

function classifyLogAlert(text) {
  const content = String(text || '').toLowerCase();
  if (!content) return 'empty';

  if (/sess[aã]o expirada|fa[çc]a login novamente|status code 401|\b401\b|unauthorized/.test(content)) {
    return 'auth-session-expired';
  }
  if (/status code 403|\b403\b|forbidden/.test(content)) {
    return 'auth-forbidden';
  }
  if (/status code 404|\b404\b|not found/.test(content)) {
    return 'http-404';
  }
  if (/status code 5\d\d|\b5\d\d\b/.test(content)) {
    return 'http-5xx';
  }
  if (/axioserror/.test(content)) {
    const statusMatch = content.match(/status code\s*(\d{3})/);
    if (statusMatch) return `axios-status-${statusMatch[1]}`;
  }
  if (/econnrefused|refused/.test(content)) return 'network-refused';
  if (/etimedout|timeout/.test(content)) return 'network-timeout';
  if (/enoent/.test(content)) return 'file-not-found';
  if (/database|sql/.test(content) && /error|failed|timeout|exception/.test(content)) return 'database-error';

  return normalizeErrorSignature(
    content
      .replace(/ at .*$/g, '')
      .replace(/[a-z]:\\[^\s)]+/gi, 'path')
      .replace(/\([^)]*\)/g, '')
      .replace(/"[^"]+"/g, '"text"')
      .replace(/'[^']+'/g, "'text'")
  );
}

function isPotentialErrorLine(source, text) {
  const content = String(text || '').trim();
  if (!content) return false;
  if (source === 'deploy') return false;
  if (/\b(?:INFO|DEBUG)\b/.test(content) && !LOG_ERROR_PATTERNS.some(rx => rx.test(content))) return false;
  if (LOG_ERROR_IGNORE_PATTERNS.some(rx => rx.test(content))) return false;
  return LOG_ERROR_PATTERNS.some(rx => rx.test(content));
}

async function notifyAppLogError(appName, source, text) {
  if (!isPotentialErrorLine(source, text)) return;

  const signature = `${appName}:${source}:${classifyLogAlert(text)}`;
  const lastSent = logAlertThrottle.get(signature) || 0;
  if (Date.now() - lastSent < APP_ERROR_DUP_WINDOW_MS) return;
  logAlertThrottle.set(signature, Date.now());

  rememberRuntimeAlert(appName, 'runtime', text);
  addErrorHistory({
    time: now(),
    app: appName,
    type: 'runtime',
    source,
    detail: text,
  });
  const recent = (logBuffers[appName] || []).slice(-6).map(entry => `${entry.source}: ${trimText(entry.text, 180)}`);
  await notifyWhatsApp(`🔴 Erro da aplicação — ${appLabel(appName)}`, [
    `📱 App: ${appName}`,
    `📌 Origem: ${source}`,
    `⚠️ Linha: ${trimText(text, 260)}`,
    recent.length ? '' : null,
    recent.length ? '📄 Últimas linhas:' : null,
    recent.length ? recent.join('\n') : null,
  ]);
}

async function notifyGitPollError(appName, message) {
  const signature = `${appName}:${normalizeErrorSignature(message)}`;
  const lastSent = gitAlertThrottle.get(signature) || 0;
  if (Date.now() - lastSent < GIT_ALERT_DUP_WINDOW_MS) return;
  gitAlertThrottle.set(signature, Date.now());
  rememberRuntimeAlert(appName, 'git', message);
  addErrorHistory({
    time: now(),
    app: appName,
    type: 'git',
    source: 'polling',
    detail: message,
  });
  await notifyWhatsApp(`⛔ Falha Git/Polling — ${appLabel(appName)}`, [
    `📱 App: ${appName}`,
    `⚠️ Erro: ${trimText(message, 300)}`,
  ]);
}

async function notifyPm2EventError(appName, event) {
  const criticalEvents = new Set(['exit overlimit', 'restart overlimit', 'errored']);
  if (!criticalEvents.has(String(event || '').toLowerCase())) return;

  const signature = `${appName}:pm2-event:${String(event).toLowerCase()}`;
  const lastSent = logAlertThrottle.get(signature) || 0;
  if (Date.now() - lastSent < PM2_EVENT_DUP_WINDOW_MS) return;
  logAlertThrottle.set(signature, Date.now());

  rememberRuntimeAlert(appName, 'runtime', `evento PM2: ${event}`);
  addErrorHistory({
    time: now(),
    app: appName,
    type: 'pm2',
    source: 'pm2',
    detail: `evento PM2: ${event}`,
  });
  await notifyWhatsApp(`🔴 Evento crítico PM2 — ${appLabel(appName)}`, [
    `📱 App: ${appName}`,
    `⚠️ Evento: ${event}`,
  ]);
}

function sortAppsByCardOrder(list) {
  const orderMap = new Map(cardOrder.map((name, index) => [name, index]));
  return [...list].sort((a, b) => {
    const ai = orderMap.has(a.name) ? orderMap.get(a.name) : Number.MAX_SAFE_INTEGER;
    const bi = orderMap.has(b.name) ? orderMap.get(b.name) : Number.MAX_SAFE_INTEGER;
    if (ai !== bi) return ai - bi;
    return appLabel(a.name).localeCompare(appLabel(b.name), 'pt-BR');
  });
}

function now() {
  return new Date().toLocaleString('pt-BR', { timeZone: 'America/Sao_Paulo' });
}

const LOG_MAX      = 300;
const logBuffers   = {};
const sseClients   = {};
const historySSE   = [];
const errorHistory = [];
const errorSSE = [];
let errorSeq = 0;

function pushHistory() {
  const data = `data: ${JSON.stringify(deployHistory)}\n\n`;
  historySSE.forEach(r => { try { r.write(data); } catch {} });
}

function pushErrorHistory() {
  (async () => {
    try {
      const list = await fetchErrorsFromDB();
      const data = `data: ${JSON.stringify(list)}\n\n`;
      errorSSE.forEach(r => { try { r.write(data); } catch {} });
    } catch (e) {
      console.error('[pushErrorHistory] erro ao buscar DB:', e.message);
    }
  })();
}

async function fetchErrorsFromDB() {
  try {
    const pool = await getPool();
    const eRes = await pool.request().query(`
      SELECT TOP 200
        ID_ERRO, APLICACAO, TIPO, ORIGEM, DETALHE, RESUMO, DTVISTO,
        FORMAT(DTINC, 'dd/MM/yyyy HH:mm:ss') AS TEMPO
      FROM dbo.CINI_MANAGER_ERRO_HISTORICO
      ORDER BY ID_ERRO DESC
    `);
    const list = [];
    let seq = 0;
    for (const r of eRes.recordset) {
      list.push({
        id:      ++seq,
        time:    r.TEMPO,
        app:     r.APLICACAO,
        type:    r.TIPO   || 'runtime',
        source:  r.ORIGEM || '',
        detail:  r.DETALHE || '',
        preview: r.RESUMO  || trimText(r.DETALHE || '', 170),
        seen:    !!r.DTVISTO,
      });
    }
    return list;
  } catch (e) {
    console.error('[db] fetchErrorsFromDB:', e.message);
    return [];
  }
}

function addDeployHistory(rec) {
  deployHistory.unshift(rec);
  if (deployHistory.length > 100) deployHistory.pop();
  pushHistory();
  (async () => {
    try {
      const pool = await getPool();
      await pool.request()
        .input('aplicacao', sql.NVarChar(100),    String(rec.app    || ''))
        .input('status',    sql.NVarChar(20),     String(rec.status || 'ok'))
        .input('detalhe',   sql.NVarChar(sql.MAX), String(rec.detail || ''))
        .query(`INSERT INTO dbo.CINI_MANAGER_DEPLOY_HISTORICO (APLICACAO, STATUS, DETALHE, DTINC)
                VALUES (@aplicacao, @status, @detalhe, GETDATE())`);
    } catch (e) {
      console.error('[db] addDeployHistory ERRO:', e.message);
    }
  })();
}

function addErrorHistory(entry) {
  const fullDetail = String(entry?.detail || '').trim();
  const rec = {
    id: ++errorSeq,
    time: entry?.time || now(),
    app: entry?.app || 'desconhecido',
    type: entry?.type || 'runtime',
    source: entry?.source || '',
    detail: fullDetail,
    preview: trimText(fullDetail, 170),
    seen: false,
  };
  errorHistory.unshift(rec);
  if (errorHistory.length > 200) errorHistory.pop();
  pushErrorHistory();
  (async () => {
    try {
      const pool = await getPool();
      await pool.request()
        .input('aplicacao', sql.NVarChar(100),     rec.app)
        .input('tipo',      sql.NVarChar(30),      rec.type)
        .input('origem',    sql.NVarChar(50),      rec.source || '')
        .input('detalhe',   sql.NVarChar(sql.MAX), rec.detail)
        .input('resumo',    sql.NVarChar(300),     rec.preview)
        .query(`INSERT INTO dbo.CINI_MANAGER_ERRO_HISTORICO (APLICACAO, TIPO, ORIGEM, DETALHE, RESUMO, DTINC)
                VALUES (@aplicacao, @tipo, @origem, @detalhe, @resumo, GETDATE())`);
    } catch (e) {
      console.error('[db] addErrorHistory ERRO:', e.message);
      // remove da memória para não mostrar o que não foi salvo no banco
      const idx = errorHistory.indexOf(rec);
      if (idx !== -1) errorHistory.splice(idx, 1);
      pushErrorHistory();
    }
  })();
}

async function ackErrorsInDB(appName) {
  try {
    const pool = await getPool();
    const req = pool.request();
    req.input('aplicacao', sql.NVarChar(100), appName);
    const result = await req.query(`
      UPDATE dbo.CINI_MANAGER_ERRO_HISTORICO
      SET    DTVISTO = GETDATE()
      WHERE  APLICACAO = @aplicacao
        AND  DTVISTO IS NULL
    `);
    console.log(`[db] ackErrorsInDB app="${appName}" linhas atualizadas=${result.rowsAffected?.[0] ?? '?'}`);
  } catch (e) {
    console.error('[db] ack errors:', e.message);
  }
}

async function loadHistoriesFromDB() {
  try {
    const pool = await getPool();

    const dRes = await pool.request().query(`
      SELECT TOP 100
        APLICACAO, STATUS, DETALHE,
        FORMAT(DTINC, 'dd/MM/yyyy HH:mm:ss') AS TEMPO
      FROM dbo.CINI_MANAGER_DEPLOY_HISTORICO
      ORDER BY ID_DEPLOY DESC
    `);
    deployHistory.length = 0;
    for (const r of dRes.recordset) {
      deployHistory.push({ time: r.TEMPO, app: r.APLICACAO, status: r.STATUS, detail: r.DETALHE || '' });
    }

    const eRes = await pool.request().query(`
      SELECT TOP 200
        ID_ERRO, APLICACAO, TIPO, ORIGEM, DETALHE, RESUMO, DTVISTO,
        FORMAT(DTINC, 'dd/MM/yyyy HH:mm:ss') AS TEMPO
      FROM dbo.CINI_MANAGER_ERRO_HISTORICO
      ORDER BY ID_ERRO DESC
    `);
    errorHistory.length = 0;
    errorSeq = 0;
    for (const r of eRes.recordset) {
      errorHistory.push({
        id:      ++errorSeq,
        time:    r.TEMPO,
        app:     r.APLICACAO,
        type:    r.TIPO   || 'runtime',
        source:  r.ORIGEM || '',
        detail:  r.DETALHE || '',
        preview: r.RESUMO  || trimText(r.DETALHE || '', 170),
        seen:    !!r.DTVISTO,
      });
    }

    // Restaurar acknowledgedAlertAt a partir da ultima confirmacao por app
    const ackRes = await pool.request().query(`
      SELECT APLICACAO, MAX(DTVISTO) AS ULTIMA_CONFIRMACAO
      FROM   dbo.CINI_MANAGER_ERRO_HISTORICO
      WHERE  DTVISTO IS NOT NULL
      GROUP  BY APLICACAO
    `);
    for (const r of ackRes.recordset) {
      if (r.ULTIMA_CONFIRMACAO) {
        acknowledgedAlertAt.set(r.APLICACAO, new Date(r.ULTIMA_CONFIRMACAO).getTime());
      }
    }

    console.log(`[db] historicos: ${deployHistory.length} deploys, ${errorHistory.length} erros`);
  } catch (e) {
    console.error('[db] loadHistoriesFromDB:', e.message);
  }
}

function bufferLog(appName, source, text) {
  if (!logBuffers[appName]) logBuffers[appName] = [];
  const entry = { time: new Date().toISOString(), source, text };
  logBuffers[appName].push(entry);
  if (logBuffers[appName].length > LOG_MAX) logBuffers[appName].shift();
  (sseClients[appName] || []).forEach(r => {
    try { r.write(`data: ${JSON.stringify(entry)}\n\n`); } catch {}
  });
  if (appName && text && ['stdout', 'stderr', 'pm2'].includes(source)) {
    notifyAppLogError(appName, source, text).catch(() => {});
  }
}

function getLatestErrorFromBuffer(appName) {
  const list = logBuffers[appName] || [];
  for (let i = list.length - 1; i >= 0; i--) {
    const entry = list[i];
    if (isPotentialErrorLine(entry.source, entry.text)) {
      return entry.text;
    }
  }
  return null;
}

let _pm2Connected = null;
function ensurePm2() {
  if (_pm2Connected) return _pm2Connected;
  _pm2Connected = new Promise((resolve, reject) => {
    pm2.connect(false, (err) => {
      if (err) { _pm2Connected = null; return reject(err); }
      resolve();
    });
  });
  return _pm2Connected;
}

function startBus() {
  ensurePm2().then(() => {
    pm2.launchBus((err, bus) => {
      if (err) { setTimeout(startBus, 5000); return; }
      console.log('[dashboard] PM2 bus ativo.');
      bus.on('log:out', pkt => {
        const name = pkt.process?.name;
        const text = (pkt.data || '').trim();
        if (name && text) bufferLog(name, 'stdout', text);
      });
      bus.on('log:err', pkt => {
        const name = pkt.process?.name;
        const text = (pkt.data || '').trim();
        if (name && text) bufferLog(name, 'stderr', text);
      });
      bus.on('process:event', pkt => {
        const name  = pkt.process?.name;
        const event = pkt.event;
        if (!name) return;
        bufferLog(name, 'pm2', `evento PM2: ${event}`);
        notifyPm2EventError(name, event).catch(() => {});
      });
      bus.on('error', () => { _pm2Connected = null; setTimeout(startBus, 5000); });
    });
  }).catch(() => setTimeout(startBus, 5000));
}
startBus();

// Periodicamente busca novos erros no DB e notifica clientes SSE (captura inserts externos)
setInterval(() => {
  try { pushErrorHistory(); } catch (e) { console.error('[poll-errors-db] erro:', e.message); }
}, 5000);

function pm2Do(action, target) {
  return ensurePm2().then(() => new Promise((resolve, reject) => {
    pm2[action](target, (err) => {
      if (err) return reject(err);
      resolve();
    });
  }));
}

async function pm2Reload(appName, log, retries = 5, delayMs = 2000) {
  for (let i = 0; i < retries; i++) {
    try {
      await pm2Do('reload', appName);
      return;
    } catch (err) {
      const msg = (err.message || err.msg || String(err)).toLowerCase();
      if (msg.includes('reload in progress') && i < retries - 1) {
        log('deploy', `⏳ PM2 reload em andamento, aguardando ${delayMs / 1000}s... (tentativa ${i + 1}/${retries})`);
        await new Promise(r => setTimeout(r, delayMs));
      } else {
        throw err;
      }
    }
  }
}

function pm2List() {
  return ensurePm2().then(() => new Promise((resolve, reject) => {
    pm2.list((err, list) => {
      if (err) return reject(err);
      resolve(list);
    });
  }));
}

function inferLogSource(filePath) {
  const n = path.basename(String(filePath || '')).toLowerCase();
  if (n.includes('error') || n.includes('-err')) return 'stderr';
  if (n.includes('pm2')) return 'pm2';
  return 'stdout';
}

function pushLogFile(files, seen, label, filePath, source, mtimeOverride) {
  if (!filePath) return;
  const full = path.resolve(filePath);
  const key = full.toLowerCase();
  if (seen.has(key) || !fs.existsSync(full)) return;
  try {
    const stat = fs.statSync(full);
    if (!stat.isFile()) return;
    seen.add(key);
    files.push({
      label,
      path: full,
      source: source || inferLogSource(full),
      mtime: Number.isFinite(mtimeOverride) ? mtimeOverride : stat.mtimeMs,
    });
  } catch {}
}

async function getAppLogFiles(appName) {
  const files = [];
  const seen = new Set();

  try {
    const list = await pm2List();
    const proc = list.find(p => p.name === appName);
    const env = proc?.pm2_env || {};
    pushLogFile(files, seen, 'PM2 stdout', env.pm_out_log_path, 'stdout');
    pushLogFile(files, seen, 'PM2 stderr', env.pm_err_log_path, 'stderr');
    pushLogFile(files, seen, 'PM2 runtime', env.pm_log_path, 'pm2');
  } catch {}

  if (!files.length) {
    const cwd = APP_REGISTRY[appName];
    if (cwd) {
      const cwdWin = cwd.replace(/\//g, path.sep);
      const searchDirs = [cwdWin, path.join(cwdWin, 'logs'), path.join(cwdWin, 'log')];
      for (const dir of searchDirs) {
        if (!fs.existsSync(dir)) continue;
        let entries;
        try { entries = fs.readdirSync(dir); } catch { continue; }
        for (const f of entries) {
          if (!f.endsWith('.log')) continue;
          pushLogFile(files, seen, f, path.join(dir, f), inferLogSource(f));
        }
      }
    }

    const pm2Home = process.env.PM2_HOME || path.join(process.env.USERPROFILE || 'C:/Users/nerias.sousa', '.pm2');
    const pm2LogDir = path.join(pm2Home, 'logs');
    if (fs.existsSync(pm2LogDir)) {
      try {
        const entries = fs.readdirSync(pm2LogDir).filter(f => f.startsWith(appName + '-') && f.endsWith('.log'));
        for (const f of entries) {
          pushLogFile(files, seen, `PM2: ${f}`, path.join(pm2LogDir, f), inferLogSource(f), 0);
        }
      } catch {}
    }
  }

  files.sort((a, b) => b.mtime - a.mtime);
  return files;
}

async function pm2Info(name) {
  try {
    const list = await pm2List();
    const p = list.find(x => x.name === name);
    if (!p) return null;
    const mem = Math.round((p.monit?.memory ?? 0) / 1024 / 1024);
    const cpu = p.monit?.cpu ?? 0;
    const upMs = p.pm2_env?.status === 'online' ? Date.now() - p.pm2_env.pm_uptime : 0;
    const upM = Math.floor(upMs / 60000);
    return {
      status: p.pm2_env?.status || '?',
      mem, cpu, upM,
      restarts: p.pm2_env?.restart_time || 0,
      pid: p.pid,
    };
  } catch { return null; }
}

function readPm2ErrorLog(name, lines = 8) {
  try {
    const pm2Home = process.env.PM2_HOME || path.join(process.env.USERPROFILE || 'C:/Users/nerias.sousa', '.pm2');
    let errFile = path.join(pm2Home, 'logs', `${name}-error.log`);
    if (!fs.existsSync(errFile)) {
      const dir = path.join(pm2Home, 'logs');
      const files = fs.readdirSync(dir).filter(f => f.startsWith(name + '-error'));
      if (!files.length) return '';
      errFile = path.join(dir, files[0]);
    }
    const stat = fs.statSync(errFile);
    const TAIL = 4096;
    const start = Math.max(0, stat.size - TAIL);
    const fd = fs.openSync(errFile, 'r');
    const buf = Buffer.alloc(Math.min(stat.size, TAIL));
    fs.readSync(fd, buf, 0, buf.length, start);
    fs.closeSync(fd);
    let text = buf.toString('utf8');
    if (start > 0) text = text.substring(text.indexOf('\n') + 1);
    const allLines = text.split('\n').filter(Boolean);
    return allLines.slice(-lines).join('\n');
  } catch { return ''; }
}

async function waitOnline(name, maxMs = 25000) {
  const deadline = Date.now() + maxMs;
  while (Date.now() < deadline) {
    await new Promise(r => setTimeout(r, 2000));
    try {
      const list = await pm2List();
      const p = list.find(x => x.name === name);
      if (p?.pm2_env?.status === 'online') return true;
    } catch {}
  }
  return false;
}

async function httpSmoke(appName, maxMs = 15000) {
  const port = readAppPort(appName);
  if (!port) return true; 
  const http = require('http');
  const deadline = Date.now() + maxMs;
  while (Date.now() < deadline) {
    await new Promise(r => setTimeout(r, 2000));
    const ok = await new Promise(resolve => {
      const req = http.get({ host: 'localhost', port, path: '/', timeout: 4000 }, res => {
        resolve(res.statusCode < 500);
      });
      req.on('error', () => resolve(false));
      req.on('timeout', () => { req.destroy(); resolve(false); });
    });
    if (ok) return true;
  }
  return false;
}

async function stagedTest(appName, cwdWin, log) {
  const { spawn } = require('child_process');
  const http = require('http');
  const prodPort = KNOWN_PORTS[appName] || 9999;
  const testPort = prodPort + 1;
  const scriptFile = path.join(cwdWin, 'server.js');
  if (!fs.existsSync(scriptFile)) {
    log('deploy', '⚠️  stagedTest: server.js não encontrado, pulando teste em porta temporária');
    return true;
  }

  log('deploy', `🔬 Iniciando instância de teste na porta ${testPort}...`);
  const child = spawn(process.execPath, [scriptFile], {
    cwd:   cwdWin,
    env:   { ...process.env, DASHBOARD_PORT: String(testPort) },
    stdio: 'pipe',
    detached: false,
  });

  let errOutput = '';
  child.stderr?.on('data', d => { errOutput += d.toString().slice(-500); });
  child.stdout?.on('data', () => {});

  let testOk = false;
  try {
    const deadline = Date.now() + 25000;
    while (Date.now() < deadline) {
      await new Promise(r => setTimeout(r, 2000));
      if (child.exitCode !== null) {
        log('deploy', `❌ Instância de teste encerrou prematuramente (exit ${child.exitCode})`);
        if (errOutput) log('deploy', errOutput.trim().split('\n').slice(-3).join(' | '));
        break;
      }
      const ok = await new Promise(resolve => {
        const req = http.get({ host: 'localhost', port: testPort, path: '/', timeout: 4000 }, res => {
          resolve(res.statusCode < 500);
        });
        req.on('error',   () => resolve(false));
        req.on('timeout', () => { req.destroy(); resolve(false); });
      });
      if (ok) { testOk = true; break; }
    }
    if (testOk) {
      log('deploy', `✅ Instância de teste OK na porta ${testPort}`);
    } else {
      log('deploy', `❌ Instância de teste não respondeu na porta ${testPort}`);
      if (errOutput) log('deploy', errOutput.trim().split('\n').slice(-3).join(' | '));
    }
    return testOk;
  } finally {
    try { child.kill('SIGTERM'); } catch {}
  }
}

const GIT_ENV = {
  ...process.env,
  GIT_TERMINAL_PROMPT: '0',
  GIT_ASKPASS: '',
  GCM_INTERACTIVE: 'never',
};

function git(args, cwd) {
  try {
    const parts = args.match(/(?:[^\s"]+|"[^"]*")+/g) || [];
    return execFileSync('git', parts, { cwd, encoding: 'utf8', timeout: 15000, stdio: ['ignore','pipe','ignore'], env: GIT_ENV }).trim();
  } catch { return null; }
}

function gitAsync(args, cwd, interactive, timeoutMs) {
  return new Promise(resolve => {
    const parts = args.match(/(?:[^\s"]+|"[^"]*")+/g) || [];
    execFile('git', parts, {
      cwd, encoding: 'utf8',
      timeout: timeoutMs || (interactive ? 120000 : 30000),
      env: interactive ? process.env : GIT_ENV,
    }, (err, stdout) => {
      resolve(err ? null : (stdout || '').trim());
    });
  });
}

function findGitRoot(appCwd) {
  const cwdWin = appCwd.replace(/\//g, path.sep);
  if (fs.existsSync(path.join(cwdWin, '.git'))) return appCwd;
  const parent = path.dirname(cwdWin).replace(/\\/g, '/');
  if (fs.existsSync(path.join(parent, '.git'))) return parent;
  const grandparent = path.dirname(parent);
  if (fs.existsSync(path.join(grandparent, '.git'))) return grandparent.replace(/\\/g, '/');
  return null;
}

function getPathFilter(appCwd, gitRoot) {
  const normApp  = appCwd.replace(/\\/g, '/').replace(/\/$/, '');
  const normRoot = gitRoot.replace(/\\/g, '/').replace(/\/$/, '');
  if (normApp !== normRoot && normApp.startsWith(normRoot + '/')) {
    return normApp.slice(normRoot.length + 1);
  }
  return null;
}

async function fixRemoteUrls() {
  const results = [];
  const seen = new Set();
  for (const [appName, cwd] of Object.entries(APP_REGISTRY)) {
    if (DEPLOY_EXCLUDE.has(appName)) continue;
    const gitRoot = findGitRoot(cwd);
    if (!gitRoot || seen.has(gitRoot)) continue;
    seen.add(gitRoot);
    try {
      const url = execFileSync('git', ['remote', 'get-url', 'origin'], {
        cwd: gitRoot, encoding: 'utf8', timeout: 5000,
      }).trim();
      const m = url.match(/^https:\/\/github\.com\/([^\/]+)\//);
      if (!m) continue;
      const owner = m[1];
      const newUrl = url.replace('https://github.com/', `https://${owner}@github.com/`);
      execFileSync('git', ['remote', 'set-url', 'origin', newUrl], {
        cwd: gitRoot, encoding: 'utf8', timeout: 5000,
      });
      results.push({ app: appName, owner });
      console.log(`[auth] ${appName}: remote → ${owner}@github.com`);
    } catch {}
  }
  return results;
}

function gitInfo(appName) {
  const cwd = APP_REGISTRY[appName];
  const gitRoot = findGitRoot(cwd);
  if (!cwd || !gitRoot) {
    return { hasGit: false };
  }
  const pathFilter = getPathFilter(cwd, gitRoot);
  const pathSuffix = pathFilter ? ` -- ${pathFilter}` : '';
  git('fetch --quiet', gitRoot);
  const branch  = git('rev-parse --abbrev-ref HEAD', gitRoot) || 'main';
  const current = git(`log -1 --format=%h|||%s|||%ar|||%an${pathSuffix}`, gitRoot);
  const [hash = '', subject = '', date = '', author = ''] = (current || '').split('|||');
  const pendingRaw = git(`log HEAD..origin/${branch} --format=%h|||%s|||%ar|||%an${pathSuffix}`, gitRoot);
  const pending = pendingRaw
    ? pendingRaw.split('\n').filter(Boolean).map(l => {
        const [h, s, d, a] = l.split('|||');
        return { hash: h, subject: s, date: d, author: a };
      })
    : [];
  const recentRaw = git(`log -10 --format=%h|||%s|||%ar|||%an${pathSuffix}`, gitRoot);
  const recent = recentRaw
    ? recentRaw.split('\n').filter(Boolean).map(l => {
        const [h, s, d, a] = l.split('|||');
        return { hash: h, subject: s, date: d, author: a };
      })
    : [];
  return { hasGit: true, branch, hash, subject, date, author, pending, recent, gitRoot };
}

const deployLock    = new Set();
const deployHistory = [];
const DEPLOY_LOCK_FILE = path.join(__dirname, '.deploy.lock');

function acquireFileLock(appName) {
  try {
    if (fs.existsSync(DEPLOY_LOCK_FILE)) {
      const existing = JSON.parse(fs.readFileSync(DEPLOY_LOCK_FILE, 'utf8'));
      if (Date.now() - existing.ts < 5 * 60 * 1000) return false;
    }
    fs.writeFileSync(DEPLOY_LOCK_FILE, JSON.stringify({ appName, ts: Date.now(), pid: process.pid }), 'utf8');
    return true;
  } catch { return false; }
}

function releaseFileLock() {
  try { fs.unlinkSync(DEPLOY_LOCK_FILE); } catch {}
}
const lastCommitCache = new Map();

async function getLastCommit(appName) {
  const cached = lastCommitCache.get(appName);
  if (cached && Date.now() - cached.ts < 60000) return cached.data;
  const cwd = APP_REGISTRY[appName];
  if (!cwd) return null;
  const gitRoot = findGitRoot(cwd);
  if (!gitRoot) return null;
  const pathFilter = getPathFilter(cwd, gitRoot);
  const pathSuffix = pathFilter ? ` -- ${pathFilter}` : '';
  const raw = await gitAsync(`log -1 --format=%h|||%s|||%ar${pathSuffix}`, gitRoot);
  if (!raw) return null;
  const [hash, subject, date] = raw.split('|||');
  const data = { hash: hash?.trim(), subject: subject?.trim(), date: date?.trim() };
  lastCommitCache.set(appName, { ts: Date.now(), data });
  return data;
}

function getLocalChanges(cwd) {
  const status = git('status --porcelain', cwd);
  return status ? status.split('\n').filter(Boolean) : [];
}

function getUnpushedCommits(cwd) {
  const branch = git('rev-parse --abbrev-ref HEAD', cwd) || 'main';
  git('fetch --quiet', cwd);
  const raw = git(`log origin/${branch}..HEAD --format=%h|||%s|||%ar|||%an`, cwd);
  return raw ? raw.split('\n').filter(Boolean).map(l => {
    const [h, s, d, a] = l.split('|||');
    return { hash: h, subject: s, date: d, author: a };
  }) : [];
}

function installDeps(cwd, cwdWin, log) {
  if (fs.existsSync(path.join(cwdWin, 'package.json'))) {
    log('deploy', 'npm install --omit=dev...');
    try {
      const out = execSync('npm install --omit=dev', { cwd, encoding: 'utf8', timeout: 120000 });
      log('deploy', out.trim() || 'concluído');
    } catch (e) { throw new Error('npm install falhou: ' + e.message.split('\n')[0]); }
  }
  if (fs.existsSync(path.join(cwdWin, 'requirements.txt'))) {
    log('deploy', 'pip install -r requirements.txt...');
    try {
      const out = execSync('pip install -r requirements.txt', { cwd, encoding: 'utf8', timeout: 120000 });
      log('deploy', out.trim().split('\n').slice(-3).join('\n') || 'concluído');
    } catch (e) { throw new Error('pip install falhou: ' + e.message.split('\n')[0]); }
  }
}

async function deployApp(appName) {
  if (deployLock.has(appName)) throw new Error('Deploy já em andamento');
  if (STAGED_DEPLOY_APPS.has(appName) && !acquireFileLock(appName)) throw new Error('Deploy já em andamento (outra instância)');
  deployLock.add(appName);

  const cwd    = APP_REGISTRY[appName];
  const cwdWin = cwd.replace(/\//g, path.sep);
  const log    = (src, txt) => { bufferLog(appName, src, txt); console.log(`[deploy:${appName}] ${txt}`); };

  try {
    log('deploy', `━━━ DEPLOY INICIADO — ${now()} ━━━`);
    const gitRoot = findGitRoot(cwd);

    if (gitRoot) {
      const localChanges    = getLocalChanges(gitRoot);
      const unpushedCommits = getUnpushedCommits(gitRoot);
      const hasLocal        = localChanges.length > 0 || unpushedCommits.length > 0;

      if (hasLocal) {
        if (localChanges.length > 0) {
          log('deploy', `📝 ${localChanges.length} alteração(ões) local(is) não commitada(s):`);
          localChanges.forEach(l => log('deploy', `   ${l}`));
        }
        if (unpushedCommits.length > 0) {
          log('deploy', `📤 ${unpushedCommits.length} commit(s) não publicado(s):`);
          unpushedCommits.forEach(c => log('deploy', `   ${c.hash} — ${c.subject}`));
        }

        installDeps(cwd, cwdWin, log);
        if (STAGED_DEPLOY_APPS.has(appName)) {
          log('deploy', '🧪 Testando em instância temporária antes de subir produção...');
          const staged = await stagedTest(appName, cwdWin, log);
          if (!staged) throw new Error('❌ Teste em porta temporária falhou. Alterações NÃO foram commitadas nem publicadas.');
          log('deploy', '✅ Teste OK — commitando antes de reiniciar...');
          if (localChanges.length > 0) {
            log('deploy', 'git add .');
            const addOut = git('add .', gitRoot);
            if (addOut === null) throw new Error('git add falhou');
            const commitMsg = `deploy(${appName}): alterações do servidor — ${now()}`;
            log('deploy', `git commit -m "${commitMsg}"...`);
            try {
              execSync(`git -c user.name="CINI Manager" -c user.email="deploy@cini.com.br" commit -m "${commitMsg}"`,
                { cwd: gitRoot, encoding: 'utf8', timeout: 15000 });
            } catch (e) { throw new Error('git commit falhou: ' + e.message.split('\n')[0]); }
            log('deploy', 'Commit criado');
          }
          log('deploy', 'git push...');
          try {
            execSync('git push', { cwd: gitRoot, encoding: 'utf8', timeout: 30000 });
          } catch (e) { throw new Error('git push falhou: ' + e.message.split('\n')[0]); }
          log('deploy', 'Push OK');
          log('deploy', '🔄 Agendando restart via processo filho (pm2 restart)...');
          const pm2Path = require.resolve('pm2');
          const restartCode = `const pm2=require(${JSON.stringify(pm2Path)});setTimeout(()=>{pm2.connect(e=>{if(!e)pm2.restart(${JSON.stringify(appName)},()=>pm2.disconnect());});},1500);`;
          const { spawn: spawnRestart } = require('child_process');
          spawnRestart(process.execPath, ['-e', restartCode], { detached: true, stdio: 'ignore', cwd: __dirname }).unref();
        } else {
          log('deploy', '🧪 Testando alterações (restart + verificação)...');
          await pm2Do('restart', appName);
          log('deploy', 'Aguardando processo online...');
          const online = await waitOnline(appName);
          if (!online) throw new Error('❌ Teste falhou — app não ficou online. Alterações NÃO foram commitadas.');
          log('deploy', '🌐 Verificando resposta HTTP...');
          const httpOk = await httpSmoke(appName);
          if (!httpOk) throw new Error('❌ Smoke test falhou — app está online no PM2 mas não responde via HTTP. Alterações NÃO foram commitadas.');
          log('deploy', '✅ Teste OK — app rodando e respondendo corretamente');
          if (localChanges.length > 0) {
            log('deploy', 'git add .');
            const addOut = git('add .', gitRoot);
            if (addOut === null) throw new Error('git add falhou');
            const commitMsg = `deploy(${appName}): alterações do servidor — ${now()}`;
            log('deploy', `git commit -m "${commitMsg}"...`);
            try {
              execSync(`git -c user.name="CINI Manager" -c user.email="deploy@cini.com.br" commit -m "${commitMsg}"`,
                { cwd: gitRoot, encoding: 'utf8', timeout: 15000 });
            } catch (e) { throw new Error('git commit falhou: ' + e.message.split('\n')[0]); }
            log('deploy', 'Commit criado');
          }
          log('deploy', 'git push...');
          try {
            execSync('git push', { cwd: gitRoot, encoding: 'utf8', timeout: 30000 });
          } catch (e) { throw new Error('git push falhou: ' + e.message.split('\n')[0]); }
          log('deploy', 'Push OK');
        }

        const commitAfter = git('rev-parse --short HEAD', gitRoot);
        const branch = git('rev-parse --abbrev-ref HEAD', gitRoot) || 'main';
        log('deploy', `━━━ DEPLOY OK — alterações publicadas (${commitAfter}) ━━━`);

        const info = await pm2Info(appName);
        const wppMsg = `✅ *Deploy OK* — ${appName}\n📅 ${now()}\n${'━'.repeat(25)}\n\n` +
          `📱 *App:* ${appName}\n` +
          `📂 *Modo:* Alterações locais\n` +
          `🌿 *Branch:* ${branch}\n` +
          `🔄 *Commit:* \`${commitAfter}\`\n` +
          (localChanges.length ? `📝 *Arquivos alterados:* ${localChanges.length}\n` : '') +
          (unpushedCommits.length ? `📤 *Commits publicados:* ${unpushedCommits.length}\n` : '') +
          `\n✅ Testado, commitado e publicado com sucesso` +
          (info ? `\n\n📊 *Status:* ${info.status} | PID ${info.pid}\n💾 *Memória:* ${info.mem}MB | ⚡ CPU: ${info.cpu}%` : '');
        await sendWhatsApp(wppMsg);

        const rec = { time: now(), app: appName, status: 'ok', detail: `alterações publicadas (${commitAfter})` };
        addDeployHistory(rec);
        return rec;
      } else {
        const commitBefore = git('rev-parse --short HEAD', gitRoot);
        const branch = git('rev-parse --abbrev-ref HEAD', gitRoot) || 'main';
        log('deploy', 'git pull...');
        const pullOut = git('pull', gitRoot);
        if (pullOut === null) throw new Error('git pull falhou');
        log('deploy', pullOut || '(sem alterações)');
        const commitAfter = git('rev-parse --short HEAD', gitRoot);
        const changed = commitBefore && commitAfter && commitBefore !== commitAfter;

        installDeps(cwd, cwdWin, log);
        let testPassed;
        if (STAGED_DEPLOY_APPS.has(appName)) {
          log('deploy', '🧪 Testando em instância temporária antes de subir produção...');
          const staged = await stagedTest(appName, cwdWin, log);
          if (staged) {
            log('deploy', '🚀 Teste OK — promovendo para produção (pm2 reload)...');
            await pm2Reload(appName, log);
            const online = await waitOnline(appName);
            testPassed = online;
            if (!online) log('deploy', '❌ pm2 reload falhou — produção não ficou online.');
          } else {
            testPassed = false;
          }
        } else {
          log('deploy', '🧪 Testando código atualizado (restart + verificação)...');
          await pm2Do('restart', appName);
          log('deploy', 'Aguardando processo online...');
          const online = await waitOnline(appName);
          const httpOkRemote = online ? await (async () => {
            log('deploy', '🌐 Verificando resposta HTTP...');
            const ok = await httpSmoke(appName);
            if (ok) log('deploy', '✅ HTTP OK');
            return ok;
          })() : false;
          testPassed = online && httpOkRemote;
        }

        if (!testPassed && changed) {
          log('deploy', `❌ Teste falhou — fazendo rollback para ${commitBefore}...`);
          git(`reset --hard ${commitBefore}`, gitRoot);
          installDeps(cwd, cwdWin, log);
          await pm2Do('restart', appName);
          const backOnline = await waitOnline(appName);
          log('deploy', backOnline
            ? `⏪ Rollback OK — voltou para ${commitBefore} e está online`
            : `⚠️ Rollback feito para ${commitBefore} mas app continua offline`);

          const errLogs = readPm2ErrorLog(appName, 10);
          const rollbackInfo = await pm2Info(appName);
          const rollbackWpp = `❌ *Deploy FALHOU* — ${appName}\n📅 ${now()}\n${'━'.repeat(25)}\n\n` +
            `📂 *Modo:* Atualização remota\n` +
            `🌿 *Branch:* ${branch}\n` +
            `🔄 *Commits:* \`${commitBefore}\` → \`${commitAfter}\`\n\n` +
            `🧪 *Teste falhou* — app não ficou online após atualização\n` +
            `⏪ *Rollback automático* para \`${commitBefore}\`\n\n` +
            `📌 *Status:* ${backOnline ? '✅ App voltou a funcionar com a versão anterior' : '⚠️ App continua offline mesmo após rollback'}` +
            (rollbackInfo ? `\n💾 Memória: ${rollbackInfo.mem}MB | Restarts: ${rollbackInfo.restarts}` : '') +
            (errLogs ? `\n\n🔴 *Últimos erros:*\n\`\`\`\n${errLogs}\n\`\`\`` : '');
          await sendWhatsApp(rollbackWpp);

          const rec = { time: now(), app: appName, status: 'error', detail: `Teste falhou (${commitAfter}) — rollback para ${commitBefore}` };
          addDeployHistory(rec);
          throw new Error(`Teste falhou — código do remoto não rodou. Rollback para ${commitBefore}`);
        }
        if (!testPassed) throw new Error(online ? 'Smoke test HTTP falhou — app não responde corretamente' : 'App não ficou online após 25s');

        log('deploy', `✅ Teste OK — app rodando e respondendo corretamente`);
        log('deploy', `━━━ DEPLOY OK ${changed ? `(${commitBefore} → ${commitAfter})` : '(sem mudanças)'} ━━━`);

        const info = await pm2Info(appName);
        const commitLog = changed ? git(`log ${commitBefore}..${commitAfter} --format=%h %s`, gitRoot) : null;
        const commitLines = commitLog ? commitLog.split('\n').filter(Boolean).slice(0, 5) : [];
        const wppMsg = `✅ *Deploy OK* — ${appName}\n📅 ${now()}\n${'━'.repeat(25)}\n\n` +
          `📱 *App:* ${appName}\n` +
          `📂 *Modo:* Atualização remota\n` +
          `🌿 *Branch:* ${branch}\n` +
          (changed
            ? `🔄 *Commit:* \`${commitBefore}\` → \`${commitAfter}\`\n` +
              (commitLines.length ? `📝 *Alterações:*\n${commitLines.map(l => `  • ${l}`).join('\n')}\n` : '')
            : `📦 Código já estava atualizado\n`) +
          `\n✅ Pull + teste + restart concluídos com sucesso` +
          (info ? `\n\n📊 *Status:* ${info.status} | PID ${info.pid}\n💾 *Memória:* ${info.mem}MB | ⚡ CPU: ${info.cpu}%` : '');
        await sendWhatsApp(wppMsg);

        const rec = { time: now(), app: appName, status: 'ok', detail: changed ? `${commitBefore} → ${commitAfter}` : 'sem mudanças' };
        addDeployHistory(rec);
        return rec;
      }
    } else {
      log('deploy', '(sem .git — pulando git)');
      installDeps(cwd, cwdWin, log);

      log('deploy', 'pm2 restart...');
      await pm2Do('restart', appName);
      log('deploy', 'Aguardando processo online...');
      const online = await waitOnline(appName);
      if (!online) throw new Error('App não ficou online após 25s');

      log('deploy', '━━━ DEPLOY OK (sem git) ━━━');
      const info = await pm2Info(appName);
      const wppMsg = `✅ *Deploy OK* — ${appName}\n📅 ${now()}\n${'━'.repeat(25)}\n\n` +
        `📱 *App:* ${appName}\n` +
        `📂 *Modo:* Sem git (restart)\n` +
        `✅ Dependências instaladas e processo reiniciado com sucesso` +
        (info ? `\n\n📊 *Status:* ${info.status} | PID ${info.pid}\n💾 *Memória:* ${info.mem}MB | ⚡ CPU: ${info.cpu}%` : '');
      await sendWhatsApp(wppMsg);

      const rec = { time: now(), app: appName, status: 'ok', detail: 'sem git' };
      addDeployHistory(rec);
      return rec;
    }
  } catch (err) {
    log('deploy', `━━━ DEPLOY FALHOU: ${err.message} ━━━`);
    const errLogs = readPm2ErrorLog(appName, 10);
    const failInfo = await pm2Info(appName);
    const gitRoot2 = findGitRoot(cwd);
    const failBranch = gitRoot2 ? git('rev-parse --abbrev-ref HEAD', gitRoot2) : null;
    const failHash = gitRoot2 ? git('rev-parse --short HEAD', gitRoot2) : null;
    const wppMsg = `❌ *Deploy FALHOU* — ${appName}\n📅 ${now()}\n${'━'.repeat(25)}\n\n` +
      (failBranch ? `🌿 *Branch:* ${failBranch}\n` : '') +
      (failHash ? `🔄 *Commit:* \`${failHash}\`\n` : '') +
      `\n⚠️ *Erro:* ${err.message}` +
      (failInfo ? `\n\n📊 *Status:* ${failInfo.status} | Restarts: ${failInfo.restarts}\n💾 Memória: ${failInfo.mem}MB` : '') +
      (errLogs ? `\n\n🔴 *Últimos erros do processo:*\n\`\`\`\n${errLogs}\n\`\`\`` : '');
    addErrorHistory({
      time: now(),
      app: appName,
      type: 'deploy',
      source: 'deploy',
      detail: err.message,
    });
    await sendWhatsApp(wppMsg);
    const rec = { time: now(), app: appName, status: 'error', detail: err.message };
    addDeployHistory(rec);
    throw err;
  } finally {
    deployLock.delete(appName);
    if (STAGED_DEPLOY_APPS.has(appName)) releaseFileLock();
  }
}

async function sendSummary() {
  try {
    const list  = await pm2List();
    const apps  = list.filter(p => !p.name.startsWith('pm2-'));
    const total = apps.length;
    const ok    = apps.filter(p => p.pm2_env.status === 'online').length;
    const down  = apps.filter(p => p.pm2_env.status !== 'online');
    const ts    = now();

    let msg = `📊 *Resumo dos Apps*\n📅 ${ts}\n${'━'.repeat(25)}\n\n`;
    msg += `✅ ${ok}/${total} online`;
    if (down.length) msg += ` | ❌ OFFLINE: ${down.map(p => p.name).join(', ')}`;
    msg += '\n\n';

    for (const p of apps) {
      const st   = p.pm2_env.status === 'online';
      const mem  = Math.round((p.monit?.memory ?? 0) / 1024 / 1024);
      const upMs = st ? Date.now() - p.pm2_env.pm_uptime : 0;
      const upH  = Math.floor(upMs / 3_600_000);
      const upM  = Math.floor((upMs % 3_600_000) / 60_000);
      msg += `${st ? '🟢' : '🔴'} *${p.name}*`;
      if (st)  msg += ` — ${mem}MB — up ${upH}h${upM}m`;
      if (p.pm2_env.restart_time > 0) msg += ` ⚠️ ${p.pm2_env.restart_time} restart(s)`;
      msg += '\n';
    }

    await sendWhatsApp(msg);
    console.log('[dashboard] Resumo 30min enviado.');
  } catch (e) {
    console.error('[dashboard] Erro resumo:', e.message);
  }
}
setInterval(sendSummary, 30 * 60 * 1000);
setTimeout(sendSummary, 90 * 1000); 
let pollingRunning = false;
let lastPollTime   = null;
let cachedGitInfo  = {};
let pollErrors     = {};
const pollErrorAt  = {};

async function refreshGitCache() {
  const info = {};
  for (const [appName, cwd] of Object.entries(APP_REGISTRY)) {
    if (DEPLOY_EXCLUDE.has(appName)) continue;
    const gitRoot = findGitRoot(cwd);
    if (!gitRoot) continue;
    info[appName] = {
      branch: await gitAsync('rev-parse --abbrev-ref HEAD', gitRoot) || 'main',
      hash:   await gitAsync('rev-parse --short HEAD', gitRoot) || '?',
      remote: await gitAsync('remote get-url origin', gitRoot) || '',
    };
  }
  cachedGitInfo = info;
}

async function pollGitUpdates() {
  if (pollingRunning || !autoPollCfg.enabled) return;
  pollingRunning = true;
  const startedAt = now();
  console.log(`[poll] Verificando atualizações em ${Object.keys(APP_REGISTRY).length} apps...`);

  for (const [appName, cwd] of Object.entries(APP_REGISTRY)) {
    if (DEPLOY_EXCLUDE.has(appName)) continue;
    if (deployLock.has(appName)) continue;
    const appCfg = autoPollCfg.apps[appName];
    if (appCfg && appCfg.enabled === false) continue;

    const gitRoot = findGitRoot(cwd);
    if (!gitRoot) continue;

    try {
      const fetchOk = await gitAsync('fetch --quiet', gitRoot, false, 8000);
      if (fetchOk === null) {
        pollErrors[appName] = 'git fetch falhou (autenticação?)';
        pollErrorAt[appName] = Date.now();
        console.error(`[poll] ${appName}: git fetch falhou`);
        await notifyGitPollError(appName, pollErrors[appName]);
        continue;
      }
      delete pollErrors[appName];
      delete pollErrorAt[appName];

      const branch     = await gitAsync('rev-parse --abbrev-ref HEAD', gitRoot) || 'main';
      const localHash  = await gitAsync('rev-parse HEAD', gitRoot);
      const remoteHash = await gitAsync(`rev-parse origin/${branch}`, gitRoot);

      if (!localHash || !remoteHash || localHash === remoteHash) continue;
      const pendingRaw = await gitAsync(`log ${localHash}..${remoteHash} --format=%h|||%s|||%an`, gitRoot);
      const pending = pendingRaw ? pendingRaw.split('\n').filter(Boolean).map(l => {
        const [h, s, a] = l.split('|||');
        return { hash: h, subject: s, author: a };
      }) : [];

      const commitList = pending.slice(0, 5)
        .map(c => `  • \`${c.hash}\` ${c.subject} (${c.author})`)
        .join('\n');

      console.log(`[poll] ${appName}: ${pending.length} commit(s) novo(s) — iniciando auto-deploy`);
      bufferLog(appName, 'deploy', `🔔 Auto-deploy: ${pending.length} commit(s) novo(s) detectado(s) no remoto`);

      await sendWhatsApp(
        `🔔 *Atualização detectada*\n📦 ${appName} (${branch})\n` +
        `📊 ${pending.length} commit(s) novo(s)\n` +
        (commitList ? `\n📝 Commits:\n${commitList}\n` : '') +
        `\n⏳ Iniciando auto-deploy...`
      );

      await deployApp(appName);
      if (!autoPollCfg.apps[appName]) autoPollCfg.apps[appName] = {};
      autoPollCfg.apps[appName].lastHash = await gitAsync('rev-parse --short HEAD', gitRoot);
      saveAutoPoll();

    } catch (e) {
      pollErrors[appName] = e.message;
      pollErrorAt[appName] = Date.now();
      console.error(`[poll] Erro ao verificar ${appName}:`, e.message);
      await notifyGitPollError(appName, e.message);
    }
  }

  lastPollTime = startedAt;
  pollingRunning = false;
  refreshGitCache();
  console.log(`[poll] Verificação concluída.`);
}

let pollTimer = null;
function startPolling() {
  if (pollTimer) clearInterval(pollTimer);
  const ms = (autoPollCfg.intervalMin || 2) * 60 * 1000;
  pollTimer = setInterval(pollGitUpdates, ms);
  console.log(`[poll] Polling ativo — verificando a cada ${autoPollCfg.intervalMin || 2} min`);
}
function stopPolling() {
  if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
  console.log('[poll] Polling desativado');
}

setTimeout(async () => {
  const fixed = await fixRemoteUrls();
  if (fixed.length) console.log(`[auth] URLs corrigidas: ${fixed.length} repos`);
  await refreshGitCache();
  console.log(`[poll] Cache git carregado: ${Object.keys(cachedGitInfo).length} apps`);
  if (autoPollCfg.enabled) {
    startPolling();
    pollGitUpdates(); 
  }
}, 15000);

const KNOWN_PORTS = {
  'client-baixas-pix':    5001,
  'portal-consultas':     3000,
  'portal-streamlit':     8501,
  'gerenciador-cargas':   8502,
  'central-notificacoes': 5000,
  'cini-dashboard':       9999,
};

function readAppPort(appName) {
  if (KNOWN_PORTS[appName]) return KNOWN_PORTS[appName];
  const cwd = APP_REGISTRY[appName];
  if (!cwd) return null;
  const cwdWin = cwd.replace(/\//g, path.sep);
  const envFile = path.join(cwdWin, '.env');
  if (fs.existsSync(envFile)) {
    try {
      const content = fs.readFileSync(envFile, 'utf8');
      for (const line of content.split('\n')) {
        const m = line.trim().match(/^[A-Z_]*PORT[A-Z_]*\s*=\s*(\d+)/i);
        if (m) return parseInt(m[1]);
      }
    } catch {}
  }

  const pkgFile = path.join(cwdWin, 'package.json');
  if (fs.existsSync(pkgFile)) {
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgFile, 'utf8'));
      const startCmd = pkg.scripts?.start || '';
      const pm = startCmd.match(/--port\s+(\d+)/i) || startCmd.match(/:(\d{4,5})/);
      if (pm) return parseInt(pm[1]);
    } catch {}
  }

  return null;
}

app.get('/api/apps', async (req, res) => {
  try {
    // buscar último erro não-visto por app direto do DB
    const latestUnseen = await (async () => {
      try {
        const pool = await getPool();
        const q = await pool.request().query(`
          SELECT APLICACAO, DETALHE, DTVISTO, FORMAT(DTINC, 'dd/MM/yyyy HH:mm:ss') AS TEMPO
          FROM dbo.CINI_MANAGER_ERRO_HISTORICO
          WHERE DTVISTO IS NULL
          ORDER BY ID_ERRO DESC
        `);
        const map = new Map();
        for (const r of q.recordset) {
          if (!map.has(r.APLICACAO)) map.set(r.APLICACAO, { detail: r.DETALHE || '', time: r.TEMPO });
        }
        return map;
      } catch (e) { return new Map(); }
    })();

    const list = await pm2List();
    const HIDE = new Set(['log-watcher']);
    const filtered = sortAppsByCardOrder(list.filter(p => !p.name.startsWith('pm2-') && !HIDE.has(p.name)));
    const commits = await Promise.all(filtered.map(p => getLastCommit(p.name).catch(() => null)));
    const lastErrors = new Map();
    for (const item of deployHistory) {
      if (item.status !== 'error') continue;
      if (!lastErrors.has(item.app)) lastErrors.set(item.app, item);
    }
    const data = filtered.map((p, i) => {
      const status = p.pm2_env.status;
      const gitError = pollErrors[p.name] || null;
      const runtimeAlert = getRuntimeAlert(p.name);
      const runtimeError = runtimeAlert?.reason || null;
      // prefer DB unseen error if present (exact payload saved in DB)
      const dbUnseen = latestUnseen.get(p.name);
      const dbError = dbUnseen ? dbUnseen.detail : null;
      const deployError = status !== 'online' ? (lastErrors.get(p.name)?.detail || null) : null;
      let attentionReason = dbError || gitError || runtimeError || deployError;
      let attentionType = dbError ? 'runtime' : (gitError ? 'git' : (runtimeError ? 'runtime' : (deployError ? 'deploy' : null)));

      const alertTs = Math.max(pollErrorAt[p.name] || 0, runtimeAlert?.ts || 0);
      const ackTs = acknowledgedAlertAt.get(p.name) || 0;
      if (attentionReason && alertTs > 0 && ackTs >= alertTs) {
        attentionReason = null;
        attentionType = null;
      }

      return {
        id:         p.pm_id,
        name:       p.name,
        status,
        cpu:        p.monit?.cpu ?? 0,
        memory:     Math.round((p.monit?.memory ?? 0) / 1024 / 1024),
        restarts:   p.pm2_env.restart_time,
        uptime:     status === 'online' ? p.pm2_env.pm_uptime : null,
        pid:        p.pid,
        port:       readAppPort(p.name),
        hasGit:     !!APP_REGISTRY[p.name] && !!findGitRoot(APP_REGISTRY[p.name]),
        deploying:  deployLock.has(p.name),
        lastCommit: commits[i] || null,
        hasAttention: !!attentionReason,
        attentionType,
        attentionReason,
        attentionTs: alertTs,
      };
    });
    res.json(data);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/apps/:name/error-detail', (req, res) => {
  (async () => {
    const { name } = req.params;
    try {
      const pool = await getPool();
      const r = await pool.request().input('aplicacao', sql.NVarChar(100), name).query(`
        SELECT TOP 12 ID_ERRO, APLICACAO, TIPO, ORIGEM, DETALHE, RESUMO, DTVISTO,
          FORMAT(DTINC, 'dd/MM/yyyy HH:mm:ss') AS TEMPO
        FROM dbo.CINI_MANAGER_ERRO_HISTORICO
        WHERE APLICACAO = @aplicacao
        ORDER BY ID_ERRO DESC
      `);
      const recent = r.recordset.map((row, i) => ({
        id: i+1,
        time: row.TEMPO,
        app: row.APLICACAO,
        type: row.TIPO || 'runtime',
        source: row.ORIGEM || '',
        detail: row.DETALHE || '',
        preview: row.RESUMO || trimText(row.DETALHE || '', 170),
        seen: !!row.DTVISTO,
      }));

      const latest = recent[0] || null;
      const runtime = getRuntimeAlert(name);
      const deployErr = deployHistory.find(item => item.app === name && item.status === 'error');
      const fromBuffer = getLatestErrorFromBuffer(name);
      const pm2ErrorTail = readPm2ErrorLog(name, 80);
      const latestFullDetail = pm2ErrorTail || latest?.detail || fromBuffer || runtime?.reason || pollErrors[name] || (deployErr ? deployErr.detail : null) || null;

      res.json({
        app: name,
        latest,
        latestFullDetail,
        pm2ErrorTail,
        runtimeAlert: runtime,
        gitError: pollErrors[name] || null,
        deployError: deployErr ? deployErr.detail : null,
        recent,
      });
    } catch (e) { res.status(500).json({ error: e.message }); }
  })();
});

app.post('/api/apps/:name/:action', async (req, res) => {
  const { name, action } = req.params;
  if (!['start','stop','restart'].includes(action))
    return res.status(400).json({ error: 'Ação inválida' });
  try {
    await pm2Do(action, name);
    if (['restart','stop','start'].includes(action)) {
      addDeployHistory({ time: now(), app: name, status: 'ok', detail: action });
    }
    await notifyWhatsApp(`✅ Ação executada — ${appLabel(name)}`, [
      `📱 App: ${name}`,
      `🔧 Ação: ${action}`,
      `📌 Origem: dashboard`,
    ]);
    res.json({ ok: true });
  } catch (e) {
    const wppMsg = `❌ *Ação falhou* — ${name}\n🔧 ${action}\n📅 ${now()}\n\n⚠️ ${e.message}`;
    sendWhatsApp(wppMsg);
    addDeployHistory({ time: now(), app: name, status: 'error', detail: `${action} falhou: ${e.message}` });
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/apps/:name/ack-errors', async (req, res) => {
  const { name } = req.params;
  console.log(`[ack] recebido para app="${name}", no registry=${!!APP_REGISTRY[name]}`);
  try {
    // limpar runtime/poll alerts localmente
    runtimeAlerts.delete(name);
    delete pollErrors[name];
    delete pollErrorAt[name];

    // atualizar DB e aguardar conclusão
    await ackErrorsInDB(name);

    // atualizar timestamp de acknowledged a partir do DB (ultima DTVISTO)
    try {
      const pool = await getPool();
      const r = await pool.request().input('aplicacao', sql.NVarChar(100), name).query(`
        SELECT MAX(DTVISTO) AS ULTIMA FROM dbo.CINI_MANAGER_ERRO_HISTORICO WHERE APLICACAO = @aplicacao
      `);
      const last = r.recordset[0]?.ULTIMA;
      if (last) acknowledgedAlertAt.set(name, new Date(last).getTime());
      else acknowledgedAlertAt.set(name, Date.now());
    } catch (e) {
      acknowledgedAlertAt.set(name, Date.now());
    }

    // notificar clientes SSE com dados frescos do DB
    pushErrorHistory();
    return res.json({ ok: true, app: name, cleared: true });
  } catch (e) {
    console.error('[ack-errors] erro:', e.message);
    return res.status(500).json({ error: e.message });
  }
});

app.post('/api/apps/reset-restarts', async (req, res) => {
  const requestedApps = Array.isArray(req.body?.apps) ? req.body.apps : [];
  const appNames = [...new Set(requestedApps.filter(name => APP_REGISTRY[name]))];
  if (!appNames.length) return res.status(400).json({ error: 'Nenhuma aplicação válida foi selecionada' });

  const results = [];
  for (const name of appNames) {
    try {
      await pm2Do('reset', name);
      addDeployHistory({ time: now(), app: name, status: 'ok', detail: 'reset restarts' });
      results.push({ app: name, ok: true });
    } catch (e) {
      addDeployHistory({ time: now(), app: name, status: 'error', detail: `reset restarts falhou: ${e.message}` });
      results.push({ app: name, ok: false, error: e.message });
    }
  }

  const failed = results.filter(item => !item.ok);
  if (failed.length) {
    await notifyWhatsApp('⚠️ Limpeza de restarts com falha parcial', [
      '📌 Origem: dashboard',
      `✅ Sucesso: ${results.filter(item => item.ok).map(item => appLabel(item.app)).join(', ') || 'nenhum'}`,
      `❌ Falha: ${failed.map(item => `${appLabel(item.app)} (${trimText(item.error, 120)})`).join(', ')}`,
    ]);
    return res.status(500).json({
      error: `Falha ao limpar ${failed.length} aplicação(ões)`,
      results,
    });
  }

  await notifyWhatsApp('🧹 Restarts limpos', [
    '📌 Origem: dashboard',
    `📱 Apps: ${appNames.map(appLabel).join(', ')}`,
    `🔢 Quantidade: ${appNames.length}`,
  ]);

  res.json({ ok: true, results });
});

app.post('/api/all/:action', async (req, res) => {
  const { action } = req.params;
  if (!['stop','restart'].includes(action))
    return res.status(400).json({ error: 'Ação inválida' });
  try {
    await pm2Do(action, 'all');
    addDeployHistory({ time: now(), app: 'TODOS', status: 'ok', detail: action });
    await notifyWhatsApp('✅ Ação em lote executada', [
      '📱 Escopo: todos os apps',
      `🔧 Ação: ${action}`,
      '📌 Origem: dashboard',
    ]);
    res.json({ ok: true });
  } catch (e) {
    const wppMsg = `❌ *Ação falhou* — TODOS\n🔧 ${action}\n📅 ${now()}\n\n⚠️ ${e.message}`;
    sendWhatsApp(wppMsg);
    addDeployHistory({ time: now(), app: 'TODOS', status: 'error', detail: `${action} falhou` });
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/apps/:name/logfiles', async (req, res) => {
  const { name } = req.params;
  const lines = parseInt(req.query.lines) || 1200;
  const results = await getAppLogFiles(name);
  if (!results.length) return res.json([]);

  const output = [];
  for (const f of results.slice(0, 4)) {
    try {
      const stat = fs.statSync(f.path);
      const TAIL_BYTES = 512 * 1024;
      const start = Math.max(0, stat.size - TAIL_BYTES);
      const fd = fs.openSync(f.path, 'r');
      const buf = Buffer.alloc(Math.min(stat.size, TAIL_BYTES));
      fs.readSync(fd, buf, 0, buf.length, start);
      fs.closeSync(fd);
      let text = buf.toString('utf8');
      if (start > 0) text = text.substring(text.indexOf('\n') + 1);
      const allLines = text.split('\n').filter(Boolean);
      const tail = allLines.slice(-lines);
      output.push({ file: f.label, source: f.source, lines: tail });
    } catch {}
  }

  res.json(output);
});

app.get('/api/apps/:name/git', (req, res) => {
  try { res.json(gitInfo(req.params.name)); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/apps/:name/deploy-check', (req, res) => {
  const { name } = req.params;
  const cwd = APP_REGISTRY[name];
  if (!cwd) return res.status(404).json({ error: 'App não encontrado' });
  const gitRoot = findGitRoot(cwd);

  if (!gitRoot) return res.json({ hasGit: false, mode: 'no-git' });

  const localChanges    = getLocalChanges(gitRoot);
  const unpushedCommits = getUnpushedCommits(gitRoot);
  const branch          = git('rev-parse --abbrev-ref HEAD', gitRoot) || 'main';
  const pendingRaw      = git(`log HEAD..origin/${branch} --format=%h|||%s`, gitRoot);
  const remotePending   = pendingRaw ? pendingRaw.split('\n').filter(Boolean).map(l => { const [h, s] = l.split('|||'); return { hash: h, subject: s }; }) : [];

  const hasLocal  = localChanges.length > 0 || unpushedCommits.length > 0;
  const mode      = hasLocal ? 'local-changes' : (remotePending.length > 0 ? 'remote-updates' : 'up-to-date');

  res.json({ hasGit: true, mode, branch, localChanges, unpushedCommits, remotePending });
});

app.get('/api/apps/:name/commit-diff', async (req, res) => {
  const { name } = req.params;
  const hash = (req.query.hash || '').replace(/[^a-fA-F0-9]/g, '').slice(0, 40);
  const cwd = APP_REGISTRY[name];
  if (!cwd) return res.status(404).json({ error: 'App não encontrado' });
  const gitRoot = findGitRoot(cwd);
  if (!gitRoot) return res.status(400).json({ error: 'Sem repositório git' });
  const ref = hash || 'HEAD';
  const stat = await gitAsync(`show --stat --format= ${ref}`, gitRoot);
  const rawDiff = await gitAsync(`show --format= ${ref}`, gitRoot);
  if (rawDiff === null) return res.status(500).json({ error: 'git show falhou' });
  const lines = rawDiff.split('\n').slice(0, 4000);
  res.json({ hash: ref, stat: stat || '', lines });
});

app.get('/api/apps/:name/readme', (req, res) => {
  const { name } = req.params;
  const cwd = APP_REGISTRY[name];
  if (!cwd) return res.status(404).json({ error: 'App não encontrado' });
  const cwdWin = cwd.replace(/\//g, path.sep);
  const readmePath = path.join(cwdWin, 'README.md');
  if (!fs.existsSync(readmePath)) return res.status(404).json({ error: 'README.md não encontrado' });
  try {
    const content = fs.readFileSync(readmePath, 'utf8');
    res.json({ content });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/apps/:name/pull', async (req, res) => {
  const { name } = req.params;
  const cwd = APP_REGISTRY[name];
  if (!cwd) return res.status(404).json({ error: 'App não encontrado' });
  const gitRoot = findGitRoot(cwd);
  if (!gitRoot) return res.status(400).json({ error: 'Sem repositório git' });
  const out = git('pull', gitRoot);
  if (out === null) {
    await notifyWhatsApp(`❌ Git pull falhou — ${appLabel(name)}`, [
      `📱 App: ${name}`,
      '📌 Origem: dashboard',
      '⚠️ Erro: git pull falhou',
    ]);
    return res.status(500).json({ error: 'git pull falhou' });
  }
  await notifyWhatsApp(`⬇ Git pull executado — ${appLabel(name)}`, [
    `📱 App: ${name}`,
    '📌 Origem: dashboard',
    `📝 Resultado: ${trimText(out || 'sem mudanças', 250)}`,
  ]);
  res.json({ ok: true, output: out });
});

app.post('/api/cards/order', async (req, res) => {
  const requestedApps = Array.isArray(req.body?.apps) ? req.body.apps : [];
  const validApps = Object.keys(APP_REGISTRY).filter(name => !DEPLOY_EXCLUDE.has(name));
  const appNames = [...new Set(requestedApps.filter(name => validApps.includes(name)))];
  if (!appNames.length) return res.status(400).json({ error: 'Ordem inválida' });

  const missing = validApps.filter(name => !appNames.includes(name));
  cardOrder = [...appNames, ...missing];
  saveCardOrder();

  await notifyWhatsApp('↕ Ordem dos cards alterada', [
    '📌 Origem: dashboard',
    `📋 Nova ordem: ${cardOrder.map(appLabel).join(' → ')}`,
  ]);

  res.json({ ok: true, apps: cardOrder });
});

app.post('/api/deploy/:name', async (req, res) => {
  const { name } = req.params;
  if (!APP_REGISTRY[name]) return res.status(404).json({ error: 'App não encontrado' });
  try {
    const rec = await deployApp(name);
    res.json(rec);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/deploy-all', (req, res) => {
  const names = Object.keys(APP_REGISTRY).filter(n => !DEPLOY_EXCLUDE.has(n));
  res.json({ ok: true, apps: names });
  (async () => {
    await notifyWhatsApp('🚀 Deploy All iniciado', [
      '📌 Origem: dashboard',
      `📱 Apps: ${names.map(appLabel).join(', ')}`,
    ]);
    for (const name of names) {
      try { await deployApp(name); } catch {}
    }
  })();
});

const fileTailState = {};
function consumeFileTail(fp) {
  const st = fileTailState[fp];
  if (!st || st.reading || st.watchers.size === 0) return;
  st.reading = true;
  try {
    const newStat = fs.statSync(fp);
    if (newStat.size <= st.size) {
      st.size = newStat.size;
      st.reading = false;
      return;
    }
    const fd = fs.openSync(fp, 'r');
    const buf = Buffer.alloc(Math.min(newStat.size - st.size, 32768));
    fs.readSync(fd, buf, 0, buf.length, st.size);
    fs.closeSync(fd);
    st.size = newStat.size;

    const lines = buf.toString('utf8').split('\n').filter(Boolean);
    for (const [app, source] of st.watchers.entries()) {
      for (const line of lines) bufferLog(app, source, line.trim());
    }
  } catch {}
  st.reading = false;
}

async function startFileTail(appName) {
  const files = await getAppLogFiles(appName);
  for (const f of files) {
    const fp = f.path;
    if (!fileTailState[fp]) {
      try {
        const stat = fs.statSync(fp);
        fileTailState[fp] = { size: stat.size, watchers: new Map(), watcher: null, poller: null, reading: false };
      } catch { continue; }
    }
    fileTailState[fp].watchers.set(appName, f.source || 'stdout');
    if (!fileTailState[fp].watcher) {
      fileTailState[fp].watcher = fs.watch(fp, { persistent: false }, () => consumeFileTail(fp));
    }
    if (!fileTailState[fp].poller) {
      fileTailState[fp].poller = setInterval(() => consumeFileTail(fp), 1500);
    }
  }
}

function stopFileTail(appName) {
  for (const [fp, st] of Object.entries(fileTailState)) {
    st.watchers.delete(appName);
    if (st.watchers.size === 0) {
      if (st.watcher) {
        st.watcher.close();
        st.watcher = null;
      }
      if (st.poller) {
        clearInterval(st.poller);
        st.poller = null;
      }
      delete fileTailState[fp];
    }
  }
}

app.get('/api/apps/:name/logs', (req, res) => {
  const { name } = req.params;
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders();
  (logBuffers[name] || []).forEach(e => {
    try { res.write(`data: ${JSON.stringify(e)}\n\n`); } catch {}
  });

  if (!sseClients[name]) sseClients[name] = [];
  sseClients[name].push(res);
  startFileTail(name).catch(() => {});
  const keepalive = setInterval(() => {
    try { res.write(': keepalive\n\n'); } catch { clearInterval(keepalive); }
  }, 15000);

  req.on('close', () => {
    clearInterval(keepalive);
    sseClients[name] = (sseClients[name] || []).filter(r => r !== res);
    if (!sseClients[name] || sseClients[name].length === 0) {
      stopFileTail(name);
    }
  });
});

app.get('/api/deploy-history', (req, res) => res.json(deployHistory));
app.get('/api/errors-history', async (req, res) => {
  try {
    const list = await fetchErrorsFromDB();
    res.json(list);
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/errors-history/stream', async (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders();
  try {
    const list = await fetchErrorsFromDB();
    res.write(`data: ${JSON.stringify(list)}\n\n`);
  } catch (e) {
    console.error('[errors-history/stream] erro ao buscar DB:', e.message);
    res.write(`data: []\n\n`);
  }

  errorSSE.push(res);
  const keepalive = setInterval(() => {
    try { res.write(': keepalive\n\n'); } catch { clearInterval(keepalive); }
  }, 15000);
  req.on('close', () => {
    clearInterval(keepalive);
    const i = errorSSE.indexOf(res);
    if (i !== -1) errorSSE.splice(i, 1);
  });
});
app.get('/api/errors-history/:id', (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!Number.isFinite(id)) return res.status(400).json({ error: 'ID inválido' });
  const item = errorHistory.find(x => x.id === id);
  if (!item) return res.status(404).json({ error: 'Erro não encontrado' });
  res.json(item);
});
app.get('/api/status', async (req, res) => {
  try {
    const list  = await pm2List();
    const apps  = list.filter(p => !p.name.startsWith('pm2-'));
    const total = apps.length;
    const ok    = apps.filter(p => p.pm2_env.status === 'online').length;
    res.json({ total, online: ok, offline: total - ok, time: now() });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/deploy-history/stream', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();
  res.write(`data: ${JSON.stringify(deployHistory)}\n\n`);

  historySSE.push(res);
  req.on('close', () => {
    const i = historySSE.indexOf(res);
    if (i !== -1) historySSE.splice(i, 1);
  });
});

app.get('/api/autopoll/config', (req, res) => {
  const appStatus = {};
  for (const [appName] of Object.entries(APP_REGISTRY)) {
    if (DEPLOY_EXCLUDE.has(appName)) continue;
    const cached = cachedGitInfo[appName];
    if (!cached) continue;
    const appCfg = autoPollCfg.apps[appName] || {};
    const safeRemote = (cached.remote || '').replace(/\/\/[^@]+@/, '//');
    appStatus[appName] = {
      enabled: appCfg.enabled !== false,
      branch: cached.branch,
      hash: cached.hash,
      remote: safeRemote,
      lastHash: appCfg.lastHash || null,
      error: pollErrors[appName] || null,
    };
  }
  res.json({
    enabled: autoPollCfg.enabled,
    intervalMin: autoPollCfg.intervalMin || 2,
    lastPoll: lastPollTime,
    polling: pollingRunning,
    apps: appStatus,
  });
});

app.get('/api/groups', async (req, res) => {
  try {
    const groups = await listServiceGroups();
    res.json(groups);
  } catch (e) {
    res.status(500).json({ error: `Falha ao carregar grupos: ${e.message}` });
  }
});

app.post('/api/groups', async (req, res) => {
  try {
    const created = await createServiceGroup(req.body?.name, req.body?.apps);
    await notifyWhatsApp('🗂 Grupo criado no dashboard', [
      `📛 Grupo: ${created.name}`,
      `📱 Serviços: ${created.apps.map(appLabel).join(', ')}`,
      '📌 Origem: dashboard',
    ]);
    res.json({ ok: true, group: created });
  } catch (e) {
    res.status(400).json({ error: e.message || 'Falha ao criar grupo' });
  }
});

app.delete('/api/groups/:id', async (req, res) => {
  try {
    const removed = await deleteServiceGroup(req.params.id);
    await notifyWhatsApp('🗑 Grupo removido no dashboard', [
      `📛 Grupo: ${removed.name}`,
      '📌 Origem: dashboard',
    ]);
    res.json({ ok: true, group: removed });
  } catch (e) {
    res.status(400).json({ error: e.message || 'Falha ao excluir grupo' });
  }
});

app.post('/api/autopoll/toggle', (req, res) => {
  autoPollCfg.enabled = !autoPollCfg.enabled;
  saveAutoPoll();
  if (autoPollCfg.enabled) { startPolling(); } else { stopPolling(); }
  notifyWhatsApp('🔄 Auto-deploy alterado', [
    '📌 Origem: dashboard',
    `📡 Status: ${autoPollCfg.enabled ? 'ATIVADO' : 'DESATIVADO'}`,
  ]).catch(() => {});
  res.json({ ok: true, enabled: autoPollCfg.enabled });
});

app.post('/api/autopoll/interval', (req, res) => {
  const min = parseInt(req.body.minutes);
  if (!min || min < 1 || min > 60) return res.status(400).json({ error: 'Intervalo deve ser entre 1 e 60 min' });
  autoPollCfg.intervalMin = min;
  saveAutoPoll();
  if (autoPollCfg.enabled) startPolling();
  notifyWhatsApp('⏱ Intervalo do auto-deploy alterado', [
    '📌 Origem: dashboard',
    `🕒 Novo intervalo: ${min} min`,
  ]).catch(() => {});
  res.json({ ok: true, intervalMin: min });
});

app.post('/api/autopoll/app/:name/toggle', (req, res) => {
  const { name } = req.params;
  if (!APP_REGISTRY[name]) return res.status(404).json({ error: 'App não encontrado' });
  if (!autoPollCfg.apps[name]) autoPollCfg.apps[name] = {};
  autoPollCfg.apps[name].enabled = !(autoPollCfg.apps[name].enabled !== false);
  saveAutoPoll();
  notifyWhatsApp('🧩 Auto-deploy por aplicação alterado', [
    '📌 Origem: dashboard',
    `📱 App: ${name}`,
    `📡 Status: ${autoPollCfg.apps[name].enabled ? 'ATIVADO' : 'DESATIVADO'}`,
  ]).catch(() => {});
  res.json({ ok: true, app: name, enabled: autoPollCfg.apps[name].enabled });
});

app.post('/api/autopoll/check-now', async (req, res) => {
  if (pollingRunning) return res.json({ ok: true, msg: 'Já está verificando...' });
  notifyWhatsApp('🔍 Verificação manual do auto-deploy', [
    '📌 Origem: dashboard',
    '📡 Ação: verificar agora',
  ]).catch(() => {});
  res.json({ ok: true, msg: 'Verificação iniciada' });
  setImmediate(() => pollGitUpdates());
});

loadHistoriesFromDB().then(() => {
  app.listen(PORT, () => console.log(`[dashboard] Rodando em http://localhost:${PORT}`));
}).catch(e => {
  console.error('[dashboard] ERRO ao carregar históricos do banco:', e?.message || e);
  app.listen(PORT, () => console.log(`[dashboard] Rodando em http://localhost:${PORT} (sem histórico do banco)`));
});
