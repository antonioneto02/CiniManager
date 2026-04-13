const pm2    = require('pm2');
const sql    = require('mssql');
const crypto = require('crypto');
const os     = require('os');
const { execSync } = require('child_process');
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

const IGNORE_APPS = new Set(['pm2-logrotate', 'log-watcher', 'cini-dashboard']);
const processStatus = new Map();

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

async function notify(mensagem) {
  try {
    const p = await getPool();
    await p.request()
      .input('dest', sql.NVarChar(50),   DESTINATARIO)
      .input('msg',  sql.NVarChar(4000), mensagem)
      .query(`
        INSERT INTO [dbo].[FATO_FILA_NOTIFICACOES]
          (TIPO_MENSAGEM, DESTINATARIO, MENSAGEM, STATUS, TENTATIVAS, DTINC)
        VALUES ('texto', @dest, @msg, 'PENDENTE', 0, GETDATE())
      `);
  } catch (err) {
    console.error('[log-watcher] Falha ao notificar:', err.message);
    pool = null;
  }
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

function startLogBus() {
  ensurePm2().then(() => {
    pm2.launchBus((err, bus) => {
      if (err) { setTimeout(startLogBus, 5000); return; }

      console.log('[log-watcher] Bus de logs ativo.');

      bus.on('log:out', (pkt) => {
        const name = pkt.process?.name;
        const line = (pkt.data || '').trim();
        if (!name || !line || IGNORE_APPS.has(name)) return;
        if (!isErrorLine(line)) return;
        if (shouldSend(`log:${name}:${line}`)) {
          notify(buildLogMessage(name, line, 'stdout'));
        }
      });

      bus.on('process:exception', (pkt) => {
        const name = pkt.process?.name;
        if (!name || IGNORE_APPS.has(name)) return;
        const e    = pkt.data || {};
        const line = [e.message, e.stack].filter(Boolean).join('\n');
        if (shouldSend(`exc:${name}:${line}`)) {
          notify(buildLogMessage(name, line, 'stderr'));
        }
      });

      bus.on('process:event', (pkt) => {
        const name  = pkt.process?.name;
        const event = pkt.event;
        if (!name || IGNORE_APPS.has(name)) return;
        const ts = new Date().toLocaleString('pt-BR', { timeZone: 'America/Sao_Paulo' });

        if (event === 'exit' || event === 'stop' || event === 'error') {
          const restarts = pkt.process?.pm2_env?.restart_time ?? 0;
          const jaEstaDown = processStatus.get(name) === 'down';

          if (!jaEstaDown) {
            const msg = `🚨 *Processo caiu!* — ${name}\n📅 ${ts}\n\n🔧 Evento: ${event}\n🔄 Restarts: ${restarts}\n\n💻 \`pm2 logs ${name} --lines 30\``;
            console.log(`[log-watcher] Processo caiu (primeira vez): ${name} (${event})`);
            notify(msg);
            processStatus.set(name, 'down');
          } else {
            console.log(`[log-watcher] Processo ainda caindo (restart ${restarts}): ${name} — sem nova notificação`);
          }
        }

        if (event === 'online') {
          const wasDown = processStatus.get(name) === 'down';
          if (wasDown) {
            const msg = `✅ *Processo recuperado* — ${name}\n📅 ${ts}`;
            console.log(`[log-watcher] Processo recuperado: ${name}`);
            notify(msg);
          }
          processStatus.set(name, 'online');
        }

        if (event === 'restart overlimit') {
          const msg = `🔥 *Loop de crash!* — ${name}\n📅 ${ts}\n\n⚠️ O app caiu várias vezes seguidas e o PM2 parou de reiniciar.\n\n💻 \`pm2 logs ${name} --lines 50\``;
          console.log(`[log-watcher] Restart overlimit: ${name}`);
          notify(msg);
        }
      });

      bus.on('error', (err) => {
        console.error('[log-watcher] Bus error:', err.message);
        _pm2Connected = null;
        setTimeout(startLogBus, 5000);
      });
    });
  }).catch(() => setTimeout(startLogBus, 5000));
}

const resourceAlerts = new Map();
function checkResources() {
  ensurePm2().then(() => {
    pm2.list((err, list) => {
      if (err || !list) return;

      for (const proc of list) {
        const name = proc.name;
        if (IGNORE_APPS.has(name) || proc.pm2_env.status !== 'online') continue;

        const cpu = proc.monit?.cpu ?? 0;
        const mem = Math.round((proc.monit?.memory ?? 0) / 1024 / 1024);

        const problems = [];
        if (cpu > CPU_LIMIT_PCT) problems.push(`🔥 CPU em *${cpu}%* (limite: ${CPU_LIMIT_PCT}%)`);
        if (mem > MEM_LIMIT_MB)  problems.push(`🧠 Memória em *${mem} MB* (limite: ${MEM_LIMIT_MB} MB)`);

        if (problems.length > 0) {
          const prev = resourceAlerts.get(name) || 0;
          resourceAlerts.set(name, prev + 1);

          if (prev + 1 >= 2) {
            const dedupKey = `resource:${name}:${problems.join(',')}`;
            if (shouldSend(dedupKey, 10 * 60 * 1000)) { 
              const msg = `⚠️ *Recurso alto* — ${name}\n📅 ${ts()}\n\n${problems.join('\n')}`;
              console.log(`[log-watcher] Recurso alto: ${name} — ${problems.join(', ')}`);
              notify(msg);
            }
          }
        } else {
          resourceAlerts.delete(name);
        }
      }
    });
  }).catch(() => {});
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
      const dedupKey = `disk:${drive}:${info.usedPct}`;
      if (shouldSend(dedupKey, 60 * 60 * 1000)) { 
        const msg = `💿 *Disco quase cheio!* — Drive ${drive}\n📅 ${ts()}\n\n📈 Uso: ${info.usedPct}%\n📦 Livre: ${info.freeMb} MB de ${info.totalGb} GB\n\n⚠️ Limpe logs ou arquivos temporários.`;
        console.log(`[log-watcher] Alerta de disco: ${drive} em ${info.usedPct}%`);
        notify(msg);
      }
    }
  }
}

startLogBus();
setInterval(checkResources, 2  * 60 * 1000); 
setInterval(checkDisk,      10 * 60 * 1000); 
setTimeout(checkResources, 30 * 1000);
setTimeout(checkDisk,      60 * 1000);

process.on('SIGINT',  () => { pm2.disconnect(); process.exit(0); });
process.on('SIGTERM', () => { pm2.disconnect(); process.exit(0); });
