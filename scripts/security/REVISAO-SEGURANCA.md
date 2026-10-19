# Revisão de segurança das apps (antes de expor para a internet)

Data: 16/10/2026. Escopo: as 42 apps de `fail2ban-apps.json` (38 Node, 4 Python).
Legenda: ✅ corrigido · ⚠️ pendente / decisão · ℹ️ verificado, ok

> Tudo abaixo vale só depois de rodar `aplicar-fail2ban.ps1` como Administrador (reinicia as apps).

## Críticos (corrigidos)

| App | Falha | Correção |
|---|---|---|
| **webhook-whatsapp (443)** | `/sicredi` e `/boleto` gravavam "PIX/boleto pago" na Z16010 (baixa no Protheus) com o que viesse no POST — qualquer um "pagava" títulos | ✅ webhook só dispara a reconciliação, que busca os pagamentos **na API do Sicredi (mTLS)** e grava só o confirmado pelo banco. Trava para nunca rodar dois ciclos juntos (não duplica) |
| **api-sicredi (3012)** | boleto/PIX/contas sem proteção nenhuma (dar baixa em boleto, gerar cobrança, trocar a URL de webhook do banco) | ✅ só rede da Cini (`SICREDI_ALLOWED_IPS`); callback do banco continua livre (valida `Authorization`) |
| **portal-api (3014)** | sem login: criar/apagar políticas de desconto, bonificação, tabela de preço, limpar carga na SC9 | ✅ só rede da Cini (quem chama é o PortalConsultas) |
| **whatsapp-bot (3001)** | `/enviar-mensagem`, `/enviar-imagem`, `/debug-*` abertos — mandar WhatsApp em nome da Cini | ✅ só rede da Cini |
| whatsapp-webnode (444), whatsapp-motoristas (3002), whatsapp-pix-motoristas (3006), notificador-pix (3013) | rotas internas (iniciar pagamento, limpar estado, notificar) abertas | ✅ só rede da Cini; `/webhook` (Meta) continua público |
| **api-weduu (3004)** | usuário `dev.cini` / `cini123` no código dava token da API | ✅ removido; credencial `api.weduu` só no `.env` |
| **cini-tracking (3010)** | upload de foto: NF ia direto no caminho (`../` gravava em qualquer pasta, inclusive código) e extensão livre (`.html` com script em `/uploads`) | ✅ NF saneada, só extensões de imagem/áudio, nome com sufixo aleatório |
| **cini-dashboard (9999)** | chave de sessão padrão no código e ausente no `.env` (dava para forjar login); `/api/webhook/monitor` aceitava qualquer um | ✅ chave forte no `.env`; webhook só rede da Cini (sem `.webhook-secret`) |
| **client-baixas-pix (5001)** | `/shutdown` (desliga o serviço), `/fallback`, `/processar-pix-txid` abertos | ✅ só rede da Cini |

## SQL injection
- ✅ portal-rnc `rncController.js` — 4 buscas (filiais, fornecedores, participantes, produtos) e grupos do usuário → parâmetros.
- ✅ portal-consultas `produtosControladosModel.js` — data inválida ia para o SQL → só AAAA-MM-DD.
- ✅ whatsapp-motoristas — busca por telefone → parâmetro.
- ℹ️ Demais ~240 SQL montados: parâmetros, constantes do servidor ou valores validados. Python: placeholders.

## Senhas e chaves no código
- ✅ Chave de sessão padrão + ausente no `.env` → chave forte gerada: cini-dashboard, central-tarefas, cini-pricing, wf-cini, erp-cini, portal-vagas-rh (OTP). Padrão removido do código também em portal-acoes, planner-cini, portal-rnc, portal-resultados, coleta-sac.
- ✅ Senhas do banco (`cini.tracking`, `gestao.portaria`) saíram do código do dashboard e do log-watcher (só `.env`).
- ✅ client-baixas-pix `app.py` — URL do Google Chat (key+token) → `.env`.
- ⚠️ **Trocar** as senhas que ficaram no histórico do git: `api.weduu` (combinar com a Weduu), `cini.tracking`, `gestao.portaria`, token do webhook do Google Chat.
- ⚠️ client-baixas-pix: a URL do Google Chat continua em 11 arquivos `.py` antigos que não rodam (`api*.py`, `app_novo.py`) — apagar ou limpar.

## Outros
- ✅ gerenciador-cargas (Django): `DEBUG=true` em produção (página de erro mostra código e configuração) → `false`, estáticos continuam servidos; `/admin/` do Django só rede da Cini.
- ✅ portal-streamlit: detalhes de erro escondidos (`showErrorDetails = "none"`).
- ✅ Apps Node sem `NODE_ENV=production` (31): o módulo coloca o Express em modo produção (sem stack trace na resposta de erro). Limite: o 1º pedido após reiniciar, se der erro, ainda mostra.
- ✅ portal-vagas-rh: currículos (dados pessoais) eram baixáveis sem login em `/curriculos/...` → só pela rota de admin.
- ✅ portal-marketing: redirect após login aceitava `/\site.com` (manda para site falso) → bloqueado.
- ✅ assistente-ia, gestao-importacao-pedidos, kanban-entregas (este alterava cargas sem login) → só rede da Cini.

## Bibliotecas (npm audit, dependências de produção)
- ✅ `npm audit fix` (sem `--force`, só versões compatíveis) nas 39 apps Node: **críticas 30 → 0, altas 96 → 24**. Nenhuma app passou a dar erro ao carregar. Só `package-lock.json` mudou (backup em scratchpad da sessão; também dá para voltar pelo git).
- ✅ AppTracking: faltava a biblioteca `compression` (a app não subia) — instalada.
- ℹ️ Altas restantes, não alcançáveis de fora: `nodemon`/`braces`/`chokidar` (ferramenta de desenvolvimento, não roda em produção), `puppeteer`/`whatsapp-web.js` no whatsapp-bot (download do navegador/proxy; atualizar exige versão maior e pode derrubar a sessão do WhatsApp), `xlsx` (só lê planilha local ou no navegador do usuário).
- ℹ️ Senhas antigas mantidas por decisão (continuam no histórico do git — manter os repositórios privados).

## Verificado, ok
ProtheusAuth (rotas de usuário exigem token), api-itau (restrição por IP), PortalConsultas (225 rotas, todas com `verificarSessao`), demais portais com login (portal-ete, contagens, televendas, ações, RNC, intranet, planner, central-tarefas, pricing, hub, erp, wf-cini, resultados, controle-formulário, cini-leads, coleta-sac), CentralNotificacoes (token), uploads do Marketing, downloads de anexos (Planner, Ações, RNC, Intranet, Formulários), webhook do erp-cini (token), injeção de comando (só no dashboard, com valores fixos), formulário público (escapa HTML).

## Decisões suas ⚠️
1. **solicitacao-fachada (3035) / portal-marketing**: `/api/clientes` devolve nome/fantasia/cidade de clientes ativos e `/api/trade/minhas-retiradas` lista retiradas por código de vendedor, **sem login** — usado pelos vendedores na rua. Opções: exigir login de vendedor, ou aceitar.
2. **Assinatura da Meta** nos `/webhook` do WhatsApp não é conferida (precisa do *App Secret* da Meta): dá para forjar mensagem "de" um motorista. Se tiver o App Secret, eu implemento.
3. **coleta-sac**: token do app mobile nunca expira.
4. **contagem-produtos**: etiquetas públicas por ID (QR do pallet) — IDs sequenciais, dá para listar produto/lote.
5. **portal-consultas**: `local_passwords.dict` permite login local sem Protheus (hoje vazio — manter vazio).
6. **cini-dashboard (9999)**: não abrir para a internet (controla o Docker do servidor); usar Tailscale.

## Validar depois de aplicar
- PIX/boleto Sicredi chegando na Z16010 (log `[fallback PIX] Z16010 inserido` / `fonte=fallback`) após um pagamento real.
- gerenciador-cargas abrindo com CSS (DEBUG=false).
- Login nas apps que ganharam chave de sessão nova (todos precisam entrar de novo uma vez).
- Chamadas entre apps (Protheus → Sicredi/Itaú, bot → motoristas/webnode, PortalConsultas → portal-api) funcionando.
