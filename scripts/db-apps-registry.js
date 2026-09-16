// Registro central das aplicações do CiniManager para a flag de troca de
// servidor de banco (localhost -> 177.104.136.230) e renomeação do banco
// p11_prod -> p2510 (demais bancos, ex.: dw, mantêm o nome).
//
// status:
//  - "safe": host e (quando aplicável) nome do banco vêm 100% de variáveis
//    de ambiente no .env, sem literal "p11_prod" embutido em queries SQL.
//    Elegível para troca automática via apply-db-target.js.
//  - "needs-code-fix": tem "p11_prod" escrito literalmente em texto de
//    query SQL (ex.: "[p11_prod].[dbo].[TABELA]"). A troca da flag por si
//    só não resolve — o código precisa ser corrigido para usar a env var
//    antes de habilitar esta app para troca automática.
//  - "special": não segue o padrão .env (sem variável de host/banco, ou
//    valores hardcoded fora do padrão "localhost"). Precisa de tratamento
//    individual.
//
// Levantamento feito em 2026-09-15 (ver histórico da conversa para detalhes
// arquivo:linha de cada ocorrência hardcoded).

module.exports = [
  // ── Grupo A: seguro para troca automática (host apenas) ──────────────
  { name: 'whatsapp-bot', pm2Name: 'whatsapp-bot', envPath: 'E:/Projetos/Central-Notificacoes/whatsapp-bot/.env', status: 'safe', usesP11Prod: false },
  { name: 'whatsapp-webnode', pm2Name: 'whatsapp-webnode', envPath: 'E:/Projetos/Central-Notificacoes/WhatsAppWebNode/.env', status: 'safe', usesP11Prod: false },
  { name: 'portal-streamlit', pm2Name: 'portal-streamlit', envPath: 'C:/Projetos/PortalConsultasStreamlit/.env', status: 'safe', usesP11Prod: false },
  { name: 'gerenciador-cargas', pm2Name: 'gerenciador-cargas', envPath: 'C:/Projetos/gerenciador-cargas/.env', status: 'safe', usesP11Prod: false },
  { name: 'portal-intranet', pm2Name: 'portal-intranet', envPath: 'E:/Projetos/PortalIntranetCini/.env', status: 'safe', usesP11Prod: false },
  { name: 'portal-televendas', pm2Name: 'portal-televendas', envPath: 'E:/Projetos/PortalTelevendas/.env', status: 'safe', usesP11Prod: false },
  { name: 'solicitacao-fachada', pm2Name: 'solicitacao-fachada', envPath: 'E:/Projetos/SolicitacaoFachada/.env', status: 'safe', usesP11Prod: false },
  { name: 'portal-ete', pm2Name: 'portal-ete', envPath: 'E:/Projetos/portalETE/.env', status: 'safe', usesP11Prod: false },
  { name: 'coleta-sac', pm2Name: 'coleta-sac', envPath: 'C:/Projetos/coleta-SAC/.env', status: 'safe', usesP11Prod: false, notes: 'Tem também banco MySQL (Azure) separado, não afetado por esta flag.' },
  { name: 'lp-negocios', pm2Name: 'lp-negocios', envPath: 'E:/Projetos/LP-Negocios/.env', status: 'safe', usesP11Prod: false },
  { name: 'cini-leads', pm2Name: 'cini-leads', envPath: 'E:/Projetos/Cini-Leads/.env', status: 'safe', usesP11Prod: false },
  { name: 'central-tarefas', pm2Name: 'central-tarefas', envPath: 'E:/Projetos/Central_Tarefas/.env', status: 'safe', usesP11Prod: false, notes: 'DB_DATABASE_PROTHEUS=p11_prod existe no .env mas não é lida em nenhum código hoje (var morta); seguro atualizar mesmo assim.' },

  // ── Grupo A: seguro, e já usa p11_prod de forma limpa (só via env var) ──
  { name: 'webhook-whatsapp', pm2Name: 'webhook-whatsapp', envPath: 'C:/Projetos/WebhookWhatsAppNode/.env', status: 'safe', usesP11Prod: true },
  { name: 'api-sicredi', pm2Name: 'api-sicredi', envPath: 'E:/Projetos/API_Sicredi/.env', status: 'needs-code-fix', usesP11Prod: true, notes: 'BLOQUEADO (não é bug de código): testado em produção em 2026-09-16, gerou erro real "Invalid object name \'dw.dbo.FATO_EMAILS_REJEITADOS_PROCESSADOS\'" — essa tabela existe no dw local mas NÃO existe no dw remoto (177.104.136.230). Revertido para local. Não reativar até a tabela ser criada/replicada no servidor remoto (src/services/database.js:629-655).' },
  { name: 'kanban-entregas', pm2Name: 'kanban-entregas', envPath: 'E:/Projetos/KanbanEntregas/.env', status: 'safe', usesP11Prod: true },
  { name: 'gestao-importacao-pedidos', pm2Name: 'gestao-importacao-pedidos', envPath: 'E:/Projetos/GestaoImportacaoPedidos/.env', status: 'safe', usesP11Prod: true },

  // ── Grupo B (corrigido em 2026-09-15): tinha p11_prod hardcoded em SQL,
  // código já ajustado para ler DB_DATABASE_PROTHEUS (ou var equivalente já
  // existente no .env do app) — falta só validar contra o servidor remoto. ──
  { name: 'portal-consultas', pm2Name: 'portal-consultas', envPath: 'C:/Projetos/PortalConsultasCini/.env', status: 'safe', usesP11Prod: true, notes: 'Corrigido: contabilidadeModel.js, estoquesModel.js, FinanceiroModel.js, kardexModel.js, loginController.js, parametrosGeraisVendedoresModel.js agora usam DB_DATABASE_PROTHEUS em vez do literal "p11_prod". App mais grande do lote — testar com atenção extra. scripts/migrate_*.js (uso único, não fazem parte do servidor rodando) não foram alterados.' },
  { name: 'whatsapp-motoristas', pm2Name: 'whatsapp-motoristas', envPath: 'E:/Projetos/Central-Notificacoes/WhatsAppMotoristas/.env', status: 'safe', usesP11Prod: true, notes: 'Corrigido: server.js agora usa DB_DATABASE_PROTHEUS (variável nova, adicionada ao .env).' },
  { name: 'portal-api', pm2Name: 'portal-api', envPath: 'E:/Projetos/portalApi/.env', status: 'safe', usesP11Prod: true, notes: 'Corrigido: produtosModel.js e vendedorTabelaPrecoModel.js agora usam DB_DATABASE_PROT (já existia no .env).' },
  { name: 'api-weduu', pm2Name: 'api-weduu', envPath: 'C:/Projetos/API_Weduu/.env', status: 'safe', usesP11Prod: true, notes: 'Corrigido: politicaDescontoController.js e politicasBonificacaoController.js agora usam DB_DATABASE_PROTHEUS (variável nova, adicionada ao .env).' },
  { name: 'cini-pricing', pm2Name: 'cini-pricing', envPath: 'E:/Projetos/Cini-Pricing/.env', status: 'safe', usesP11Prod: true, notes: 'Corrigido: loginController.js agora usa DB_DATABASE_PROTHEUS (já existia no .env).' },
  { name: 'erp-cini', pm2Name: 'erp-cini', envPath: 'E:/Projetos/Gestao_Portaria/erp_cini/.env', status: 'safe', usesP11Prod: true, notes: 'Corrigido: loginController.js agora usa DB_DATABASE_PROTHEUS (já existia no .env).' },
  { name: 'portal-rnc', pm2Name: 'portal-rnc', envPath: 'E:/Projetos/PortalRNC/.env', status: 'safe', usesP11Prod: true, notes: 'Corrigido: rncController.js agora usa DB_DATABASE_PROTHEUS (variável nova, adicionada ao .env).' },
  { name: 'portal-acoes', pm2Name: 'portal-acoes', envPath: 'E:/Projetos/PortalAcoes/.env', status: 'safe', usesP11Prod: true, notes: 'Corrigido: acaoController.js (4 ocorrências) agora usa DB_DATABASE_PROTHEUS (variável nova, adicionada ao .env).' },
  { name: 'notificador-pix', pm2Name: 'notificador-pix', envPath: 'C:/Projetos/Confirmacao_Pix/NotificadorPIX/.env', status: 'safe', usesP11Prod: true, notes: 'Corrigido: databaseP11Prod.js agora usa DB_NAME_P11PROD (já existia no .env, mas era ignorada pelo código).' },
  { name: 'central-notificacoes', pm2Name: 'central-notificacoes', envPath: 'E:/Projetos/Central-Notificacoes/CentralNotificacoes/.env', status: 'safe', usesP11Prod: true, notes: 'Corrigido (Python): central_notificacoes.py agora usa DB_DATABASE_PROTHEUS (variável nova, adicionada ao .env).' },
  { name: 'portal-vagas-rh', pm2Name: 'portal-vagas-rh', envPath: 'E:/Projetos/PortalVagasRH/.env', status: 'safe', usesP11Prod: true, notes: 'Corrigido: dbConfigProtheus.js já lia DB_DATABASE_PROTHEUS do env (com fallback) — só faltava a variável existir no .env; adicionada.' },
  { name: 'assistente-ia', pm2Name: 'assistente-ia', envPath: 'E:/Projetos/AssistenteIA/.env', status: 'safe', usesP11Prod: true, notes: 'Corrigido: services/db.js (whitelist ALLOWED_DATABASES) agora usa DB_DATABASE_PROTHEUS (variável nova, adicionada ao .env). Usada em queries dinâmicas geradas por IA — testar esse fluxo específico.' },
  { name: 'wf-cini', pm2Name: 'wf-cini', envPath: 'E:/Projetos/WF_Cini/wf_cini/.env', status: 'safe', usesP11Prod: true, notes: 'Já usava DB_DATABASE_PROTHEUS corretamente (nenhuma mudança de código); monta referência cross-database "[<db>].[dbo].[SYS_USR]" a partir de outro pool — validar permissão cross-db do usuário ao testar.' },

  // ── Grupo C (parcialmente corrigido em 2026-09-15) ────────────────────
  { name: 'hub-cini', pm2Name: 'hub-cini', envPath: 'E:/Projetos/Hub_Cini/.env', status: 'safe', usesP11Prod: false, notes: 'Corrigido: código já lia DB_SERVER_TRACKING do env (com fallback "localhost") — a variável nunca existia no .env; adicionada (junto com usuário/senha de "cini.tracking"). Não usa p11_prod.' },
  { name: 'cini-dashboard', pm2Name: 'cini-dashboard', envPath: 'E:/Projetos/CiniManager/dashboard/.env', status: 'safe', usesP11Prod: false, notes: 'Corrigido: DB_CFG em dashboard/server.js estava 100% hardcoded ("localhost"/"dw"/senha) — agora lê de DB_SERVER_TRACKING/DB_DATABASE_DW/DB_TRACKING_USER/DB_TRACKING_PASSWORD (adicionadas ao .env). GROUPS_DB_CFG já lia DB_SERVER_ERP corretamente, só faltava a variável existir no .env; adicionada. Não usa p11_prod.' },
  { name: 'client-baixas-pix', pm2Name: 'client-baixas-pix', envPath: 'C:/Projetos/ClientBaixasPIX/.env', status: 'special', usesP11Prod: true, notes: 'NÃO TOCADO. Não tem .env; host hardcoded em my_models.py como "consultas.cini.com.br"/"192.168.0.43" — nunca foi "localhost", então não é claro que deva apontar para o mesmo servidor 177.104.136.230. Nomes de banco ("p11_prod"/"dw") também hardcoded. Decisão de como tratar isso precisa ser tomada com o usuário antes de qualquer mudança.' },
];
