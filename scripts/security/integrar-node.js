// Integra cini-fail2ban nas apps Node: insere require + app.use(guard) logo apos `X = express()`.
// Uso: node integrar-node.js [--dry]   (idempotente: pula apps ja integradas)
const fs = require('fs');
const path = require('path');

const DRY = process.argv.includes('--dry');
const P = 'C:\\Projetos\\';
const WEBHOOK = { rateLimit: false };

const APPS = [
  // dir, arquivo com express(), opcoes do guard
  ['AssistenteIA', 'server.js', {}],
  ['PlannerCini', 'app.js', { loginPaths: ['/login'] }],
  ['ControleFormularioQualidade', 'app.js', { loginPaths: ['/login'] }],
  ['SolicitacaoFachada', 'app.js', {}],
  ['ProtheusAuth', 'server.js', { loginPaths: ['/rest/api/oauth2/v1/token'], ignoreLoginFailFromCini: true }],
  ['PortalTelevendas', 'app.js', { loginPaths: ['/login'] }],
  ['GestaoImportacaoPedidos', 'server.js', {}],
  ['KanbanEntregas', 'server.js', {}],
  ['PortalAcoes', 'app.js', { loginPaths: ['/login'] }],
  ['PortalRNC', 'app.js', { loginPaths: ['/login'] }],
  ['PortalIntranetCini', 'app.js', { loginPaths: ['/login'] }],
  ['Cini-Leads', 'app.js', { loginPaths: ['/login'] }],
  ['coleta-SAC', 'app.js', { loginPaths: ['/login', '/api/mobile/login'] }],
  ['PortalVagasRH', 'app.js', { loginPaths: ['/login'] }],
  ['portalApi', 'server.js', {}],
  ['Central_Tarefas', 'server.js', { loginPaths: ['/login'] }],
  ['Cini-Pricing', 'server.js', { loginPaths: ['/login'] }],
  ['WF_Cini\\wf_cini', 'server.js', { loginPaths: ['/login'] }],
  ['Hub_Cini', 'server.js', { loginPaths: ['/login'] }],
  ['Gestao_Portaria\\erp_cini', 'server.js', { loginPaths: ['/login'] }],
  ['PortalConsultasCini', 'app.js', { loginPaths: ['/login'] }],
  // paradas
  ['PortalResultados', 'app.js', { loginPaths: ['/login'] }],
  ['API_Itau', 'src\\app.js', WEBHOOK],
  ['ApiSicredi', 'src\\app.js', WEBHOOK],
  ['Confirmacao_Pix\\NotificadorPIX', 'app.js', WEBHOOK],
  ['Central-Notificacoes\\WhatsAppPixMotoristas', 'server.js', WEBHOOK],
  ['Central-Notificacoes\\WhatsAppMotoristas', 'server.js', WEBHOOK],
  ['Central-Notificacoes\\whatsapp-bot', 'bot.js', WEBHOOK],
];

function containerEPorta(dir) {
  const c = fs.readFileSync(path.join(dir, 'docker-compose.yml'), 'utf8');
  return {
    name: (/container_name:\s*(\S+)/.exec(c) || [])[1],
    port: +((/-\s*"?(\d+):\d+/.exec(c) || [])[1]),
  };
}

const jsonPath = 'C:\\Projetos\\CiniManager\\scripts\\security\\fail2ban-apps.json';
const lista = JSON.parse(fs.readFileSync(jsonPath, 'utf8'));

for (const [rel, entry, opts] of APPS) {
  const dir = P + rel;
  const file = path.join(dir, entry);
  const { name, port } = containerEPorta(dir);
  let src = fs.readFileSync(file, 'utf8');
  const eol = src.includes('\r\n') ? '\r\n' : '\n';

  if (!lista.some(a => a.dir.toLowerCase() === dir.toLowerCase())) lista.push({ name, port, dir });

  if (src.includes('cini-fail2ban')) { console.log(`= ${name}: ja integrado`); continue; }
  const m = /^([ \t]*)(?:const|let|var)\s+(\w+)\s*=\s*express\(\)\s*;?[ \t]*$/m.exec(src);
  if (!m) { console.log(`! ${name}: express() nao encontrado em ${entry}`); continue; }

  const reqPath = path.relative(path.dirname(file), path.join(dir, 'security', 'cini-fail2ban')).replace(/\\/g, '/');
  const req = reqPath.startsWith('.') ? reqPath : './' + reqPath;
  const optsTxt = Object.keys(opts).length ? `, ${JSON.stringify(opts).replace(/"(\w+)":/g, '$1: ').replace(/"/g, "'").replace(/,(?=\w)/g, ', ').replace(/\[/g, '[').replace(/:\s+/g, ': ')}` : '';
  const ind = m[1];
  const bloco = `${eol}${ind}const f2b = require('${req}');${eol}${ind}${m[2]}.use(f2b.guard('${name}'${optsTxt}));`;
  const pos = m.index + m[0].length;
  src = src.slice(0, pos) + bloco + src.slice(pos);
  const linha = src.slice(0, pos).split('\n').length;
  console.log(`+ ${name} (${port}): ${entry}:${linha + 1}  ${m[2]}.use(f2b.guard('${name}'${optsTxt}))`);
  if (!DRY) { try { fs.writeFileSync(file, src); } catch (e) { console.log(`  !! SEM PERMISSAO para gravar ${file} (${e.code})`); } }
}

if (!DRY) fs.writeFileSync(jsonPath, JSON.stringify(lista, null, 2) + '\n');
console.log(`\nfail2ban-apps.json: ${lista.length} apps${DRY ? ' (dry-run, nada gravado)' : ''}`);
