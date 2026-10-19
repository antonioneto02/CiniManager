# Fail2ban (IPBan) no appserverwin

Bane no **Windows Firewall do servidor** IPs que atacam as apps expostas ou o RDP.

| Peça | Onde | O que faz |
|---|---|---|
| `cini-fail2ban.js` | fonte: `CiniManager/shared/` · cópia: `<App>/security/` | Middleware `guard()` nas apps: grava eventos em `<App>/logs/security/<tipo>-AAAA-MM-DD.log` (um arquivo por tipo) |
| IPBan (serviço `IPBAN`) | `C:\Program Files\IPBan` | Lê esses logs + evento 4625 (RDP) e cria regras de bloqueio no firewall |
| `log-watcher.js` | CiniManager | Lê `C:\Program Files\IPBan\logfile.txt` e manda WhatsApp a cada IP banido |

## Regras de banimento

| Evento | Quando é gravado | Bane após |
|---|---|---|
| `SCANNER` | caminho de ataque (`/.env`, `/.git`, `wp-login`, `.php`, `../` …) — app responde 404 | 2 |
| `RATE_LIMIT` | resposta 429 de qualquer `express-rate-limit` (máx. 1 linha/IP/min) | 3 |
| `LOGIN_FAIL` | POST no login que voltou 401/403 ou redirect `?error=invalid_credentials` / `?erro=1` | 5 |
| RDP | senha errada no Windows/RDP (evento 4625) | 5 |

Tempo de ban: 1 dia → 7 dias → 30 dias para reincidentes.
**Nunca banidos:** redes internas `10.0.0.0/8`, `172.16.0.0/12` (containers) e `192.168.0.0/16` (Protheus `192.168.0.88`), Tailscale `100.64.0.0/10`, IPs públicos da Cini `177.104.136.227`, `200.225.247.91` (consultas/afv) e `200.225.247.159` (protheus.cini.com.br), e a Weduu `35.205.198.169`. A whitelist vale para o servidor inteiro (todas as portas).
Tudo isso fica configurado no topo de `configure-ipban.ps1`.

## Instalação (PowerShell **como Administrador**, nesta ordem)

```powershell
cd C:\Projetos\CiniManager\scripts\security
.\enable-host-firewall.ps1      # liga o firewall do Windows em "permitir tudo" (nada muda no acesso)
.\configure-ipban.ps1           # instala o IPBan, aplica a config e reinicia o serviço
```
Rollback do firewall: `.\enable-host-firewall.ps1 -Rollback`.

Depois disso, e sempre que mudar algo, rode como Administrador:
```powershell
.\aplicar-fail2ban.ps1     # integra, copia módulos, confere sintaxe, reconfigura IPBan,
                           # reinicia as apps que estão rodando e o serviço cini-log-watcher
```
O `cini-log-watcher` é um serviço do Windows (NSSM), não um container.

## Alterar o módulo

Fontes: `CiniManager/shared/cini-fail2ban.js` (Node) e `CiniManager/shared/cini_fail2ban.py` (Python:
Flask, Django e Streamlit). Edite só elas e rode `.\aplicar-fail2ban.ps1`. Nova app Node: adicione em
`integrar-node.js` (lista `APPS`); nova app Python: em `fail2ban-apps.json` e integre à mão (exemplos
no topo do `.py`). Em Node, o guard entra antes de qualquer outro middleware:

```js
const f2b = require('./security/cini-fail2ban');
app.use(f2b.guard('nome-da-app', { loginPaths: ['/login'] }));
```
Opções: `loginPaths`, `loginFailRedirect` (regex), `rateLimit: false` (não grava 429),
`maxPerMinute` (limite próprio por IP, para app sem `express-rate-limit`),
`ignoreLoginFailFromCini: true` (backend de login chamado pelas outras apps — só a ProtheusAuth usa:
o erro de senha do usuário já é contado na app que chamou, então só conta quem ataca a ProtheusAuth direto de fora).

## Ver e desbanir

```powershell
Get-NetFirewallRule -DisplayName 'IPBan*' | Get-NetFirewallAddressFilter | Select-Object -ExpandProperty RemoteAddress
Get-Content 'C:\Program Files\IPBan\logfile.txt' -Tail 50
# desbanir: criar C:\Program Files\IPBan\unban.txt com um IP por linha (o serviço lê e apaga o arquivo)
'1.2.3.4' | Set-Content 'C:\Program Files\IPBan\unban.txt'
```
