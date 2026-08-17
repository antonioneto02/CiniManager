'use strict';
// Varre os logs de todos os apps do ecossistema e apaga arquivos de log com mais de
// MAX_AGE_DIAS dias. Roda uma vez e sai (agendado via cron_restart no pm2, ver
// ecosystem.new-apps.config.js). Seguro para rodar com os apps online: só mexe em
// arquivos cuja data de modificação já é antiga — um log "quente" sendo escrito agora
// sempre tem mtime recente, então nunca é candidato à exclusão.
const fs = require('fs');
const path = require('path');

const MAX_AGE_DIAS = 30;
const CUTOFF_MS = Date.now() - MAX_AGE_DIAS * 24 * 60 * 60 * 1000;

// Mesma lista de diretórios do APP_REGISTRY em dashboard/server.js.
const APP_DIRS = {
  'contagem-produtos': 'E:/Projetos/ContagemProdutos',
  'api-weduu': 'C:/Projetos/API_Weduu',
  'erp-cini': 'E:/Projetos/Gestao_Portaria/erp_cini',
  'wf-cini': 'E:/Projetos/WF_Cini/wf_cini',
  'central-tarefas': 'E:/Projetos/Central_Tarefas',
  'hub-cini': 'E:/Projetos/Hub_Cini',
  'cini-pricing': 'E:/Projetos/Cini-Pricing',
  'api-sicredi': 'E:/Projetos/API_Sicredi',
  'notificador-pix': 'C:/Projetos/Confirmacao_Pix/NotificadorPIX',
  'cini-dashboard': 'E:/Projetos/CiniManager/dashboard',
  'whatsapp-bot': 'E:/Projetos/Central-Notificacoes/whatsapp-bot',
  'webhook-whatsapp': 'C:/Projetos/WebhookWhatsAppNode',
  'client-baixas-pix': 'C:/Projetos/ClientBaixasPIX',
  'portal-consultas': 'C:/Projetos/PortalConsultasCini',
  'portal-streamlit': 'C:/Projetos/PortalConsultasStreamlit',
  'gerenciador-cargas': 'C:/Projetos/gerenciador-cargas',
  'whatsapp-motoristas': 'E:/Projetos/Central-Notificacoes/WhatsAppMotoristas',
  'whatsapp-pix-motoristas': 'E:/Projetos/Central-Notificacoes/WhatsAppPixMotoristas',
  'whatsapp-webnode': 'E:/Projetos/Central-Notificacoes/WhatsAppWebNode',
  'central-notificacoes': 'E:/Projetos/Central-Notificacoes/CentralNotificacoes',
  'portal-vagas-rh': 'E:/Projetos/PortalVagasRH',
  'portal-api': 'E:/Projetos/portalApi',
  'portal-ete': 'E:/Projetos/portalETE',
  'cini-tracking': 'E:/Projetos/AppTracking',
  'coleta-sac': 'C:/Projetos/coleta-SAC',
  'lp-negocios': 'E:/Projetos/LP-Negocios',
  'cini-leads': 'E:/Projetos/Cini-Leads',
  'portal-intranet': 'E:/Projetos/PortalIntranetCini',
  'portal-rnc': 'E:/Projetos/PortalRNC',
  'portal-acoes': 'E:/Projetos/PortalAcoes',
  'portal-resultados': 'E:/Projetos/PortalResultados',
  'kanban-entregas': 'E:/Projetos/KanbanEntregas',
  'gestao-importacao-pedidos': 'E:/Projetos/GestaoImportacaoPedidos',
  'portal-televendas': 'E:/Projetos/PortalTelevendas',
  'protheus-auth': 'E:/Projetos/ProtheusAuth',
  'portal-marketing': 'E:/Projetos/PortalMarketing',
  'contagem-armazens': 'E:/Projetos/ContagemArmazens',
  'solicitacao-fachada': 'E:/Projetos/SolicitacaoFachada',
};

const LOG_FILE_RE = /\.log(\.\d+)?(\.gz)?$/i;

function coletarArquivosDeLog(dir) {
  const achados = [];
  const logsDir = path.join(dir, 'logs');
  const pilha = [];
  if (fs.existsSync(logsDir)) pilha.push(logsDir);

  while (pilha.length) {
    const atual = pilha.pop();
    let entradas;
    try {
      entradas = fs.readdirSync(atual, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const ent of entradas) {
      const full = path.join(atual, ent.name);
      if (ent.isDirectory()) {
        pilha.push(full);
      } else if (LOG_FILE_RE.test(ent.name)) {
        achados.push(full);
      }
    }
  }

  // Também pega *.log soltos na raiz do projeto (padrão antigo usado por alguns apps).
  try {
    for (const nome of fs.readdirSync(dir)) {
      if (LOG_FILE_RE.test(nome)) {
        const full = path.join(dir, nome);
        if (fs.statSync(full).isFile()) achados.push(full);
      }
    }
  } catch {}

  return achados;
}

const DRY_RUN = process.argv.includes('--dry-run');

function limparApp(nome, dir) {
  if (!fs.existsSync(dir)) return { nome, apagados: 0, bytes: 0, erro: 'diretório não encontrado' };

  const arquivos = coletarArquivosDeLog(dir);
  let apagados = 0;
  let bytes = 0;
  const detalhes = [];

  for (const arq of arquivos) {
    let st;
    try {
      st = fs.statSync(arq);
    } catch {
      continue;
    }
    if (st.mtimeMs < CUTOFF_MS) {
      if (!DRY_RUN) {
        try {
          fs.unlinkSync(arq);
        } catch (e) {
          console.warn(`[log-cleanup] Falha ao apagar ${arq}: ${e.message}`);
          continue;
        }
      }
      apagados++;
      bytes += st.size;
      detalhes.push({ arquivo: arq, mb: (st.size / 1024 / 1024).toFixed(2), mtime: new Date(st.mtimeMs).toISOString().slice(0, 10) });
    }
  }

  return { nome, apagados, bytes, detalhes };
}

function main() {
  const inicio = Date.now();
  console.log(`[log-cleanup] ${DRY_RUN ? 'DRY-RUN (nada será apagado) ' : ''}Iniciando varredura | corte: arquivos com mais de ${MAX_AGE_DIAS} dias`);

  let totalApagados = 0;
  let totalBytes = 0;
  const resultados = [];

  for (const [nome, dir] of Object.entries(APP_DIRS)) {
    const r = limparApp(nome, dir);
    resultados.push(r);
    totalApagados += r.apagados || 0;
    totalBytes += r.bytes || 0;
    if (r.apagados > 0) {
      console.log(`[log-cleanup] ${nome}: ${r.apagados} arquivo(s) ${DRY_RUN ? 'seriam removidos' : 'removidos'}, ${(r.bytes / 1024 / 1024).toFixed(1)} MB`);
      if (DRY_RUN) {
        for (const d of r.detalhes) console.log(`    - ${d.arquivo} (${d.mb} MB, ${d.mtime})`);
      }
    }
  }

  const duracao = ((Date.now() - inicio) / 1000).toFixed(1);
  console.log(
    `[log-cleanup] Concluído em ${duracao}s | ${totalApagados} arquivo(s) removido(s) no total | ` +
    `${(totalBytes / 1024 / 1024).toFixed(1)} MB liberados`
  );
}

main();
