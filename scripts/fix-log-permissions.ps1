# Corrige a ACL das pastas "logs" de todos os apps do CiniManager para que o usuario
# que roda o dashboard (nao-administrador) consiga apagar arquivos antigos.
#
# Alguns logs antigos foram criados por um processo com dono BUILTIN\Administrators /
# NT AUTHORITY\SYSTEM, deixando o grupo Users so com leitura (sem excluir). Isso faz a
# limpeza automatica de logs (>30 dias) do CiniManager falhar com "Access is denied"
# nesses arquivos especificos, mesmo rodando dentro do proprio processo do dashboard.
#
# Rode este script UMA VEZ, como Administrador:
#   powershell -ExecutionPolicy Bypass -File fix-log-permissions.ps1

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
Write-Output "Concedendo controle total para '$usuario' nas pastas de log de cada app..."

foreach ($nome in $apps.Keys) {
  $dir = $apps[$nome]
  if (-not (Test-Path $dir)) { continue }

  # Pasta logs/ (recursivo)
  $logsDir = Join-Path $dir "logs"
  if (Test-Path $logsDir) {
    try {
      icacls $logsDir /grant "${usuario}:(OI)(CI)F" /T /C /Q | Out-Null
      Write-Output "  OK: $logsDir"
    } catch {
      Write-Warning "  Falhou em $logsDir : $($_.Exception.Message)"
    }
  }

  # *.log soltos na raiz do projeto
  Get-ChildItem -Path $dir -Filter "*.log" -File -ErrorAction SilentlyContinue | ForEach-Object {
    try {
      icacls $_.FullName /grant "${usuario}:F" /C /Q | Out-Null
    } catch {
      Write-Warning "  Falhou em $($_.FullName): $($_.Exception.Message)"
    }
  }
}

Write-Output "Concluido. Rode a limpeza de novo (ou espere a proxima varredura diaria do dashboard) para confirmar."
