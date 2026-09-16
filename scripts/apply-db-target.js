// Aplica a flag central de banco de dados (db-target.json) nas aplicações
// do CiniManager: troca o host de "localhost" <-> "177.104.136.230" e o
// nome do banco "p11_prod" <-> "p2510" nos .env de cada app registrada
// como "safe" em scripts/db-apps-registry.js, e opcionalmente reinicia via PM2.
//
// Uso:
//   node scripts/apply-db-target.js --target=remote --apps=webhook-whatsapp        (dry-run, só mostra o diff)
//   node scripts/apply-db-target.js --target=remote --apps=webhook-whatsapp --apply --restart
//   node scripts/apply-db-target.js --target=local  --apply --restart              (todas as apps "safe")
//
// Por padrão roda em modo dry-run (não escreve nada). Passe --apply para
// gravar os .env de fato, e --restart para reiniciar os processos PM2
// afetados depois de gravar. Sem --apps, afeta todas as apps com status
// "safe" no registro.

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const registry = require('./db-apps-registry');

const STATE_PATH = path.join(__dirname, '..', 'db-target.json');
const BACKUP_ROOT = path.join(__dirname, '..', 'backups', 'db-target');

function parseArgs() {
  const args = { apply: false, restart: false, apps: null, target: null };
  for (const raw of process.argv.slice(2)) {
    const [key, value] = raw.replace(/^--/, '').split('=');
    if (key === 'apply') args.apply = true;
    else if (key === 'restart') args.restart = true;
    else if (key === 'target') args.target = value;
    else if (key === 'apps') args.apps = value.split(',').map((s) => s.trim());
  }
  return args;
}

function loadState() {
  return JSON.parse(fs.readFileSync(STATE_PATH, 'utf8'));
}

function saveState(state) {
  fs.writeFileSync(STATE_PATH, JSON.stringify(state, null, 2) + '\n', 'utf8');
}

function isHostKey(key) {
  const k = key.toUpperCase();
  const hasDbMarker = k.includes('DB') || k.includes('MSSQL');
  const hasHostMarker = k.includes('SERVER') || k.includes('HOST');
  return hasDbMarker && hasHostMarker;
}

function backupEnvFile(appName, envPath, timestamp) {
  const destDir = path.join(BACKUP_ROOT, timestamp);
  fs.mkdirSync(destDir, { recursive: true });
  const dest = path.join(destDir, `${appName}.env.bak`);
  fs.copyFileSync(envPath, dest);
  return dest;
}

function applyToEnvFile(envPath, env) {
  const raw = fs.readFileSync(envPath, 'utf8');
  const eol = raw.includes('\r\n') ? '\r\n' : '\n';
  const lines = raw.split(/\r\n|\n/);
  const changes = [];

  const knownHostValues = [env.local.dbHost, env.remote.dbHost];
  const knownDbNameValues = [env.local.p11ProdDb, env.remote.p11ProdDb];
  const targetHost = env.target === 'remote' ? env.remote.dbHost : env.local.dbHost;
  const targetDbName = env.target === 'remote' ? env.remote.p11ProdDb : env.local.p11ProdDb;

  const newLines = lines.map((line) => {
    const m = line.match(/^([A-Za-z0-9_]+)=(.*)$/);
    if (!m) return line;
    const [, key, rawValue] = m;
    const trimmed = rawValue.trim();
    const quoteMatch = trimmed.match(/^(["'])(.*)\1$/);
    const quote = quoteMatch ? quoteMatch[1] : '';
    const value = quoteMatch ? quoteMatch[2] : trimmed;

    if (isHostKey(key) && knownHostValues.includes(value) && value !== targetHost) {
      changes.push({ key, from: value, to: targetHost });
      return `${key}=${quote}${targetHost}${quote}`;
    }

    if (knownDbNameValues.includes(value) && value !== targetDbName) {
      changes.push({ key, from: value, to: targetDbName });
      return `${key}=${quote}${targetDbName}${quote}`;
    }

    return line;
  });

  return { content: newLines.join(eol), changes };
}

function main() {
  const args = parseArgs();
  if (!args.target || !['local', 'remote'].includes(args.target)) {
    console.error('Uso: node apply-db-target.js --target=local|remote [--apps=a,b] [--apply] [--restart]');
    process.exit(1);
  }

  const state = loadState();
  const envDef = { local: state.environments.local, remote: state.environments.remote, target: args.target };

  let apps = registry.filter((a) => a.status === 'safe');
  if (args.apps) {
    const wanted = new Set(args.apps);
    const notFound = args.apps.filter((n) => !registry.some((a) => a.name === n));
    if (notFound.length) {
      console.error('App(s) não encontrada(s) no registro:', notFound.join(', '));
      process.exit(1);
    }
    const notSafe = registry.filter((a) => wanted.has(a.name) && a.status !== 'safe');
    if (notSafe.length) {
      console.error('Recusado: as apps abaixo NÃO estão marcadas como "safe" no registro (precisam de correção de código ou tratamento especial antes):');
      notSafe.forEach((a) => console.error(`  - ${a.name} (${a.status}): ${a.notes || ''}`));
      process.exit(1);
    }
    apps = registry.filter((a) => wanted.has(a.name));
  }

  console.log(`Alvo: ${args.target} (${envDef[args.target].label}) | modo: ${args.apply ? 'APLICAR' : 'dry-run (nada será escrito)'}`);
  console.log(`Apps no escopo: ${apps.map((a) => a.name).join(', ')}\n`);

  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const results = [];

  for (const app of apps) {
    if (!fs.existsSync(app.envPath)) {
      console.log(`[${app.name}] AVISO: .env não encontrado em ${app.envPath} — pulando.`);
      continue;
    }

    const { content, changes } = applyToEnvFile(app.envPath, envDef);

    if (changes.length === 0) {
      console.log(`[${app.name}] sem alterações (já está em "${args.target}").`);
      continue;
    }

    console.log(`[${app.name}] ${changes.length} alteração(ões):`);
    changes.forEach((c) => console.log(`    ${c.key}: ${c.from} -> ${c.to}`));

    if (args.apply) {
      const backupPath = backupEnvFile(app.name, app.envPath, timestamp);
      fs.writeFileSync(app.envPath, content, 'utf8');
      console.log(`    gravado. backup em ${backupPath}`);

      state.apps[app.name] = { target: args.target, updatedAt: new Date().toISOString() };
      results.push(app);
    }
  }

  if (args.apply) {
    saveState(state);
    console.log('\nEstado (db-target.json) atualizado.');
  }

  if (args.apply && args.restart && results.length) {
    console.log('\nReiniciando processos PM2...');
    for (const app of results) {
      try {
        const out = execSync(`pm2 restart ${app.pm2Name} --update-env`, { encoding: 'utf8' });
        console.log(`[${app.pm2Name}] reiniciado.`);
      } catch (err) {
        console.error(`[${app.pm2Name}] FALHA ao reiniciar:`, err.message);
      }
    }
  }

  if (!args.apply) {
    console.log('\nModo dry-run — nenhum arquivo foi alterado. Rode novamente com --apply para gravar (e --restart para reiniciar via PM2).');
  }
}

main();
