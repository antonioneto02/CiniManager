const sql    = require('mssql');
const crypto = require('crypto');
const { execSync } = require('child_process');
const dockerController = require('./dashboard/docker-controller');
const { APP_REGISTRY, CONTAINER_NAME_OVERRIDES } = require('./dashboard/app-registry');

const DESTINATARIO = '554188529918';
const DEDUP_WINDOW = 60 * 1000;
const CPU_LIMIT_PCT  = 85;
const MEM_LIMIT_MB   = 500;
const DISK_LIMIT_PCT = 85;
const DRIVES_TO_CHECK = ['C:', 'E:'];

const DB = {
  server:   'localhost',
  database: 'dw',
  user:     'cini.tracking',
  password: 'k00b82f6j9TO6alM',
  options:  { trustServerCertificate: true, encrypt: false },
  pool:     { max: 3, min: 0, idleTimeoutMillis: 10000 },
};

const IGNORE_APPS = new Set(['log-watcher', 'cini-dashboard']);
const processStatus = new Map(); // appName -> 'online' | 'down'
const dieTimestamps = new Map(); // appName -> [epochMs, ...] (janela de 1h p/ detectar loop de crash)
const CRASH_LOOP_WINDOW_MS = 60 * 60 * 1000;
const CRASH_LOOP_THRESHOLD = 3;

const ERROR_PATTERNS = [
  /\berror\b/i,
  /\bexception\b/i,
  /\bfailed\b/i,
  /TypeError|ReferenceError|SyntaxError|RangeError|URIError/,
  /ECONNREFUSED|ETIMEDOUT|ENOTFOUND|ECONNRESET|EPIPE/,
  /unhandledRejection|uncaughtException/i,
  /\b(4[0-9]{2}|5[0-9]{2})\b.*(?:error|fail)/i,
  /\bERRO\b/,
  /\bFALHA\b/i,
];

const SAFE_PATTERNS = [
  /\[INFO\]/,
  /\[DEBUG\]/,
  /\[TRACE\]/,
  / \[info\] /i,
  /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*\[.*\].*code \d{3}/i,
  /"(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS) \//,
  /Bad HTTP\/0\.9 request/i,
  /Bad request (?:version|syntax|type)/i,
  /message Bad /i,
  /\bHTTP\/\d\.\d"\s+\d{3}/,
  /- ERROR - \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/,
  /\[supervisor\]/, 
];

function isErrorLine(line) {
  if (SAFE_PATTERNS.some(r => r.test(line))) return false;
  return ERROR_PATTERNS.some(r => r.test(line));
}

const dedupCache = new Map();
function shouldSend(key, windowMs = DEDUP_WINDOW) {
  const hash = crypto.createHash('md5').update(key.substring(0, 300)).digest('hex');
  const now  = Date.now();
  const last = dedupCache.get(hash);
  if (last && now - last < windowMs) return false;
  dedupCache.set(hash, now);
  if (dedupCache.size > 500) {
    for (const [k, ts] of dedupCache) {
      if (now - ts > windowMs * 2) dedupCache.delete(k);
    }
  }
  return true;
}

let pool = null;
async function getPool() {
  if (pool) return pool;
  pool = await new sql.ConnectionPool(DB).connect();
  pool.on('error', (err) => {
    console.error('[log-watcher] Erro pool SQL:', err.message);
    pool = null;
  });
  return pool;
}

async function notify(mensagem, tipo = 'texto') {
  try {
    const p = await getPool();
    await p.request()
      .input('tipo', sql.NVarChar(30),   tipo)
      .input('dest', sql.NVarChar(50),   DESTINATARIO)
      .input('msg',  sql.NVarChar(4000), mensagem)
      .query(`
        INSERT INTO [dbo].[FATO_FILA_NOTIFICACOES]
          (TIPO_MENSAGEM, DESTINATARIO, MENSAGEM, STATUS, TENTATIVAS, DTINC)
        VALUES (@tipo, @dest, @msg, 'PENDENTE', 0, GETDATE())
      `);
  } catch (err) {
    console.error('[log-watcher] Falha ao notificar:', err.message);
    pool = null;
  }
}

function notifyProcessEvent(mensagem) {
  return notify(mensagem, 'google_chat_infra');
}

function stripAnsi(str) {
  return str.replace(/\x1B\[[0-9;]*[mGKHF]/g, '');
}

function ts() {
  return new Date().toLocaleString('pt-BR', { timeZone: 'America/Sao_Paulo' });
}

function buildLogMessage(appName, line, source) {
  const label = source === 'stderr' ? '🟡 STDERR' : '🔴 ERRO';
  const clean = stripAnsi(line).trim();
  return `${label} — *${appName}*\n📅 ${ts()}\n\n⚠️ ${clean.substring(0, 900)}`;
}

dockerController.init({
  appRegistry: APP_REGISTRY,
  containerOverrides: CONTAINER_NAME_OVERRIDES,
  stateDir: __dirname,
  onLog: (name, source, line) => {
    if (IGNORE_APPS.has(name) || source !== 'stdout' || !line) return;
    if (isErrorLine(line)) {
      console.error(`[log-watcher] ${name}: ${line.substring(0, 200)}`);
      if (shouldSend(`${name}:${line}`)) notify(buildLogMessage(name, line, source));
    }
  },
});

dockerController.onEvent((name, action) => {
  if (IGNORE_APPS.has(name)) return;

  if (action === 'die') {
    const jaEstaDown = processStatus.get(name) === 'down';
    if (!jaEstaDown) {
      console.log(`[log-watcher] Processo caiu (primeira vez): ${name}`);
      processStatus.set(name, 'down');
      if (shouldSend(`${name}:down`, 5 * 60 * 1000)) {
        notifyProcessEvent(`🚨 *Processo caiu!*\n📅 ${ts()}\n\n📱 App: *${name}*`);
      }
    } else {
      console.log(`[log-watcher] Processo ainda caindo: ${name}`);
    }

    const list = (dieTimestamps.get(name) || []).filter(t => Date.now() - t < CRASH_LOOP_WINDOW_MS);
    list.push(Date.now());
    dieTimestamps.set(name, list);
    if (list.length >= CRASH_LOOP_THRESHOLD && shouldSend(`${name}:crashloop`, CRASH_LOOP_WINDOW_MS)) {
      notifyProcessEvent(`🔥 *Loop de crash!*\n📅 ${ts()}\n\n📱 App: *${name}*\n${list.length} quedas na última hora.`);
    }
  }

  if (action === 'start') {
    const wasDown = processStatus.get(name) === 'down';
    if (wasDown) {
      console.log(`[log-watcher] Processo recuperado: ${name}`);
      if (shouldSend(`${name}:up`, 5 * 60 * 1000)) {
        notifyProcessEvent(`✅ *Processo recuperado*\n📅 ${ts()}\n\n📱 App: *${name}*`);
      }
    }
    processStatus.set(name, 'online');
  }
});

const resourceAlerts = new Map();
function checkResources() {
  for (const proc of dockerController.list()) {
    const name = proc.name;
    if (IGNORE_APPS.has(name) || proc.pm2_env.status !== 'online') continue;

    const cpu = proc.monit?.cpu ?? 0;
    const mem = Math.round((proc.monit?.memory ?? 0) / 1024 / 1024);

    const problems = [];
    if (mem > MEM_LIMIT_MB)  problems.push(`🧠 Memória em *${mem} MB* (limite: ${MEM_LIMIT_MB} MB)`);

    if (problems.length > 0) {
      const prev = resourceAlerts.get(name) || 0;
      resourceAlerts.set(name, prev + 1);

      if (prev + 1 >= 2) {
        console.log(`[log-watcher] Recurso alto: ${name} — ${problems.join(', ')}`);
      }
    } else {
      resourceAlerts.delete(name);
    }
  }
}

function getDiskUsage(drive) {
  try {
    const wmic = execSync(
      `wmic logicaldisk where "DeviceID='${drive}'" get Size,FreeSpace /format:csv`,
      { encoding: 'utf8', timeout: 5000 }
    );
    const lines = wmic.trim().split('\n').filter(l => l.includes(','));
    if (lines.length < 2) return null;
    const parts = lines[lines.length - 1].trim().split(',');
    const free  = parseInt(parts[1]);
    const total = parseInt(parts[2]);
    if (isNaN(free) || isNaN(total) || total === 0) return null;
    const usedPct = Math.round(((total - free) / total) * 100);
    const freeMb  = Math.round(free / 1024 / 1024);
    const totalGb = Math.round(total / 1024 / 1024 / 1024);
    return { usedPct, freeMb, totalGb };
  } catch {
    return null;
  }
}

function checkDisk() {
  for (const drive of DRIVES_TO_CHECK) {
    const info = getDiskUsage(drive);
    if (!info) continue;

    console.log(`[log-watcher] Disco ${drive}: ${info.usedPct}% usado (${info.freeMb} MB livres de ${info.totalGb} GB)`);

    if (info.usedPct >= DISK_LIMIT_PCT) {
      console.warn(`[log-watcher] Alerta de disco: ${drive} em ${info.usedPct}% (${info.freeMb} MB livres)`);
    }
  }
}

setInterval(checkResources, 2  * 60 * 1000);
setInterval(checkDisk,      10 * 60 * 1000);
setTimeout(checkResources, 30 * 1000);
setTimeout(checkDisk,      60 * 1000);
