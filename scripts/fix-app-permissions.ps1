# Corrige a ACL das pastas de projeto de todos os apps do CiniManager para que o
# usuario que roda o dashboard (nao-administrador) consiga apagar/recriar arquivos.
#
# Alguns arquivos/pastas (logs antigos, node_modules de instalacoes antigas) foram
# criados por um processo com dono BUILTIN\Administrators / NT AUTHORITY\SYSTEM,
# deixando o grupo Users so com leitura (sem excluir). Isso quebra duas coisas:
#   1) a limpeza automatica de logs (>30 dias) do CiniManager -- "Access is denied"
#   2) o auto-deploy (npm ci apos detectar push novo) -- EPERM ao recriar node_modules
#
# Rode este script UMA VEZ, como Administrador:
#   powershell -ExecutionPolicy Bypass -File fix-app-permissions.ps1

#Requires -RunAsAdministrator

$apps = @{
  'contagem-produtos'= 'E:/Projetos/ContagemProdutos'
  'api-weduu'        = 'C:/Projetos/API_Weduu'
  'erp-cini'         = 'E:/Projetos/Gestao_Portaria/erp_cini'
  'wf-cini'          = 'E:/Projetos/WF_Cini/wf_cini'
  'central-tarefas'  = 'E:/Projetos/Central_Tarefas'
  'hub-cini'         = 'E:/Projetos/Hub_Cini'
  'cini-pricing'     = 'E:/Projetos/Cini-Pricing'
  'api-sicredi'      = 'E:/Projetos/API_Sicredi'
  'notificador-pix'  = 'C:/Projetos/Confirmacao_Pix/NotificadorPIX'
  'cini-dashboard'   = 'E:/Projetos/CiniManager/dashboard'
  'whatsapp-bot'          = 'E:/Projetos/Central-Notificacoes/whatsapp-bot'
  'webhook-whatsapp'      = 'C:/Projetos/WebhookWhatsAppNode'
  'client-baixas-pix'     = 'C:/Projetos/ClientBaixasPIX'
  'portal-consultas'      = 'C:/Projetos/PortalConsultasCini'
  'portal-streamlit'      = 'C:/Projetos/PortalConsultasStreamlit'
  'gerenciador-cargas'    = 'C:/Projetos/gerenciador-cargas'
  'whatsapp-motoristas'   = 'E:/Projetos/Central-Notificacoes/WhatsAppMotoristas'
  'whatsapp-pix-motoristas' = 'E:/Projetos/Central-Notificacoes/WhatsAppPixMotoristas'
  'whatsapp-webnode'      = 'E:/Projetos/Central-Notificacoes/WhatsAppWebNode'
  'central-notificacoes'  = 'E:/Projetos/Central-Notificacoes/CentralNotificacoes'
  'portal-vagas-rh'       = 'E:/Projetos/PortalVagasRH'
  'portal-api'            = 'E:/Projetos/portalApi'
  'portal-ete'            = 'E:/Projetos/portalETE'
  'cini-tracking'         = 'E:/Projetos/AppTracking'
  'coleta-sac'            = 'C:/Projetos/coleta-SAC'
  'lp-negocios'           = 'E:/Projetos/LP-Negocios'
  'cini-leads'            = 'E:/Projetos/Cini-Leads'
  'portal-intranet'       = 'E:/Projetos/PortalIntranetCini'
  'portal-rnc'            = 'E:/Projetos/PortalRNC'
  'portal-acoes'          = 'E:/Projetos/PortalAcoes'
  'portal-resultados'     = 'E:/Projetos/PortalResultados'
  'kanban-entregas'       = 'E:/Projetos/KanbanEntregas'
  'gestao-importacao-pedidos' = 'E:/Projetos/GestaoImportacaoPedidos'
  'portal-televendas'     = 'E:/Projetos/PortalTelevendas'
  'protheus-auth'         = 'E:/Projetos/ProtheusAuth'
  'portal-marketing'      = 'E:/Projetos/PortalMarketing'
  'contagem-armazens'     = 'E:/Projetos/ContagemArmazens'
  'solicitacao-fachada'   = 'E:/Projetos/SolicitacaoFachada'
}

$usuario = "$env:USERDOMAIN\$env:USERNAME"
Write-Output "Concedendo controle total para '$usuario' na pasta inteira de cada app (logs, node_modules, etc)..."

foreach ($nome in $apps.Keys) {
  $dir = $apps[$nome]
  if (-not (Test-Path $dir)) { continue }
  try {
    icacls $dir /grant "${usuario}:(OI)(CI)F" /T /C /Q | Out-Null
    Write-Output "  OK: $nome ($dir)"
  } catch {
    Write-Warning "  Falhou em $dir : $($_.Exception.Message)"
  }
}

Write-Output "Concluido. A limpeza de logs e o auto-deploy (npm ci) devem funcionar normalmente a partir de agora."
