const sql    = require('mssql');
const crypto = require('crypto');
const fs     = require('fs');
const path   = require('path');
const { execSync } = require('child_process');
const dockerController = require('./dashboard/docker-controller');
const { APP_REGISTRY, CONTAINER_NAME_OVERRIDES } = require('./dashboard/app-registry');

const DESTINATARIO = '554188529918';
const DEDUP_WINDOW = 60 * 1000;
const CPU_LIMIT_PCT  = 85;
const MEM_LIMIT_MB   = 500;
const DISK_LIMIT_PCT = 85;
const DRIVES_TO_CHECK = ['C:', 'E:'];

// Credenciais do banco no .env do CiniManager (sem dotenv instalado aqui: leitor simples).
try {
  for (const linha of fs.readFileSync(path.join(__dirname, '.env'), 'utf8').split(/\r?\n/)) {
    const m = /^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/.exec(linha);
    if (m && process.env[m[1]] === undefined) process.env[m[1]] = m[2].replace(/^(['"])(.*)\1$/, '$2');
  }
} catch (err) {
  console.error('[log-watcher] Nao foi possivel ler .env:', err.message);
}

const DB = {
  server:   process.env.DB_SERVER_TRACKING,
  database: 'dw',
  user:     process.env.DB_TRACKING_USER,
  password: process.env.DB_TRACKING_PASSWORD,
  options:  { trustServerCertificate: true, encrypt: false },
  pool:     { max: 3, min: 0, idleTimeoutMillis: 10000 },
};

const IGNORE_APPS = new Set(['log-watcher', 'cini-dashboard']);
const processStatus = new Map(); 
const dieTimestamps = new Map(); 
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

const IPBAN_LOG = process.env.IPBAN_LOG_FILE || 'C:\\Program Files\\IPBan\\logfile.txt';
const F2B_APPS = require('./scripts/security/fail2ban-apps.json');
const F2B_MOTIVOS = {
  'CiniF2B-SCANNER':    'Robô procurando falhas: tentou abrir endereços que só ataques usam (arquivos de senha, WordPress, phpMyAdmin...).',
  'CiniF2B-RATE_LIMIT': 'Excesso de acessos: estourou o limite de requisições várias vezes (possível flood ou robô).',
  'CiniF2B-LOGIN_FAIL': 'Tentativa de adivinhar senha: errou o login várias vezes seguidas.',
  'RDP':                'Tentativa de adivinhar senha do servidor (Área de Trabalho Remota / Windows).',
};
let ipbanOffset = null;
let ipbanResto = '';
const ipbanFonte = new Map();

// Ataques do IP hoje, lendo os logs de seguranca das apps: { apps: ['portal-ete (3021)'], paths: ['/.env'] }
function ataquesDoIp(ip) {
  const dia = new Date().toISOString().substring(0, 10);
  const apps = new Set();
  const paths = new Set();
  for (const app of F2B_APPS) {
    const dir = path.join(app.dir, 'logs', 'security');
    let arquivos = [];
    try { arquivos = fs.readdirSync(dir).filter(n => n.endsWith('.log') && (n.includes(dia) || n.endsWith('-teste.log'))); } catch { continue; }
    for (const nome of arquivos) {
      let conteudo = '';
      try { conteudo = fs.readFileSync(path.join(dir, nome), 'utf8'); } catch { continue; }
      for (const linha of conteudo.split('\n')) {
        if (!linha.includes(` ip=${ip} `)) continue;
        apps.add(`${app.name} (porta ${app.port})`);
        const p = / path=(\S+)/.exec(linha);
        if (p && paths.size < 5) paths.add(p[1]);
      }
    }
  }
  return { apps: [...apps], paths: [...paths] };
}

// IPBan escreve a duracao como D.HH:MM:SS (ex.: 1.00:00:00 = 1 dia).
function duracaoLegivel(valor) {
  const m = /^(?:(\d+)\.)?(\d+):(\d+):(\d+)$/.exec(valor || '');
  if (!m) return null;
  const [dias, horas, min] = [+(m[1] || 0), +m[2], +m[3]];
  const partes = [];
  if (dias) partes.push(`${dias} ${dias === 1 ? 'dia' : 'dias'}`);
  if (horas) partes.push(`${horas}h`);
  if (min) partes.push(`${min}min`);
  const ate = new Date(Date.now() + ((dias * 24 + horas) * 60 + min) * 60000)
    .toLocaleString('pt-BR', { timeZone: 'America/Sao_Paulo', dateStyle: 'short', timeStyle: 'short' });
  return `${partes.join(' ') || 'menos de 1min'} (liberado em ${ate})`;
}

function processarLinhaIpBan(line) {
  const falha = /Login fail\w*:?\s*([0-9a-fA-F:.]+),\s*[^,]*,\s*([^,\s]+)/i.exec(line);
  if (falha) {
    ipbanFonte.set(falha[1], falha[2]);
    if (ipbanFonte.size > 2000) ipbanFonte.clear();
    return null;
  }
  if (/un-?banning/i.test(line)) return null;
  const ban = /Banning ip address:?\s*([0-9a-fA-F:.]+)/i.exec(line);
  if (!ban) return null;
  const ip = ban[1];
  const duracao = /duration:\s*([\d.:]+)/i.exec(line);
  const count = /count:\s*(\d+)/i.exec(line);
  const fonte = ipbanFonte.get(ip);
  const ataques = ataquesDoIp(ip);
  return {
    ip,
    motivo: F2B_MOTIVOS[fonte] || fonte || 'não identificado',
    apps: ataques.apps,
    paths: ataques.paths,
    count: count ? count[1] : null,
    duracao: duracao ? (duracaoLegivel(duracao[1]) || duracao[1]) : null,
  };
}

function checkIpBan() {
  fs.stat(IPBAN_LOG, (err, st) => {
    if (err) return;
    if (ipbanOffset === null) { ipbanOffset = st.size; return; }
    if (st.size < ipbanOffset) { ipbanOffset = 0; ipbanResto = ''; }
    if (st.size === ipbanOffset) return;

    const inicio = ipbanOffset;
    ipbanOffset = st.size;
    let texto = '';
    fs.createReadStream(IPBAN_LOG, { start: inicio, end: st.size - 1, encoding: 'utf8' })
      .on('data', (chunk) => { texto += chunk; })
      .on('error', (e) => console.error('[log-watcher] Erro lendo log do IPBan:', e.message))
      .on('end', () => {
        const linhas = (ipbanResto + texto).split(/\r?\n/);
        ipbanResto = linhas.pop();
        const bans = linhas.map(processarLinhaIpBan).filter(Boolean)
          .filter(b => shouldSend(`ipban:${b.ip}`, 10 * 60 * 1000));
        if (bans.length === 0) return;

        for (const b of bans) console.log(`[log-watcher] IP banido: ${b.ip} — ${b.motivo} ${b.apps.join(', ')}`);

        if (bans.length > 5) {
          const lista = bans.slice(0, 20).map(b => `• ${b.ip} — ${b.motivo}`).join('\n');
          notify(`🛡️ *${bans.length} IPs banidos* pelo IPBan\n📅 ${ts()}\n\n${lista}${bans.length > 20 ? '\n…' : ''}`);
          return;
        }
        for (const b of bans) {
          notify(`🛡️ *IP bloqueado no servidor* — appserverwin\n📅 ${ts()}\n\n`
            + `🌐 IP: *${b.ip}*\n`
            + `⚠️ Motivo: ${b.motivo}\n`
            + (b.apps.length ? `📱 App atacada: ${b.apps.join(', ')}\n` : '')
            + (b.paths.length ? `🔎 Tentou acessar: ${b.paths.join(', ')}\n` : '')
            + (b.count ? `🔁 Tentativas: ${b.count}\n` : '')
            + (b.duracao ? `⏳ Bloqueado por: ${b.duracao}\n` : '')
            + `\nEsse IP não acessa nenhuma porta do servidor até ser liberado.`);
        }
      });
  });
}

setInterval(checkResources, 2  * 60 * 1000);
setInterval(checkDisk,      10 * 60 * 1000);
setInterval(checkIpBan,     30 * 1000);
setTimeout(checkResources, 30 * 1000);
setTimeout(checkDisk,      60 * 1000);
checkIpBan();
