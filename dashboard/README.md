# 📊 Cini Dashboard — Painel de Operações

> Dashboard web para monitoramento de processos PM2 com logs ao vivo, deploy automatizado e notificações WhatsApp.

## 📋 Sobre o Projeto

O **Cini Dashboard** é um painel web de operações que dá visibilidade completa sobre todos os serviços rodando no servidor. Ele permite que a equipe de TI veja em tempo real o **status de cada aplicação PM2**, acompanhe **logs ao vivo via streaming** (SSE), execute **deploys com um clique** (git pull + npm install + PM2 restart), e receba **notificações WhatsApp** em eventos importantes.

O problema que resolve: **antes era necessário acessar o servidor via RDP, abrir terminal e rodar comandos PM2 manualmente**. Agora tudo está acessível via navegador, com feedback visual e alertas automáticos.

Além disso, a cada 30 minutos envia um **resumo automático** de todos os apps via WhatsApp, informando quais estão online, uso de memória e uptime.

## 🛠️ Tecnologias

| Tecnologia | Uso |
|---|---|
| **Node.js** | Runtime principal |
| **Express** | Framework web (API + arquivos estáticos) |
| **PM2 API** | Gerenciamento de processos (list, restart, stop, start, bus de logs) |
| **mssql** | Driver SQL Server para notificações WhatsApp |
| **child_process** | Execução de git pull, npm install |
| **SSE (Server-Sent Events)** | Streaming de logs em tempo real para o frontend |
| **Porta** | **9999** |

## 🔧 Como Funciona

### 🖥️ Interface Web

```
1. 🌐 Acesse http://servidor:9999
2. 📋 Veja a lista de todos os apps PM2:
   ├── 🟢 Online / 🔴 Offline
   ├── CPU% / Memória (MB) / Restarts
   ├── Uptime / PID / Porta
   └── Botões: Restart | Stop | Start | Deploy | Logs
3. 📜 Clique em "Logs" para streaming ao vivo (SSE)
4. 🚀 Clique em "Deploy" para git pull + restart automático
5. 📊 Acompanhe histórico de deploys em tempo real
```

### 🚀 Fluxo de Deploy

```
1. Verifica se já não há deploy em andamento (lock)
2. git pull no diretório do app
3. npm install --omit=dev (se tiver package.json)
4. pm2 restart <nome>
5. Aguarda app ficar online (até 25s)
6. Envia notificação WhatsApp: ✅ Deploy OK (commit antigo → novo)
7. Registra no histórico de deploys
```

Em caso de falha, envia ❌ Deploy FALHOU via WhatsApp com detalhes do erro.

### 📡 Resumo Automático (30 min)

A cada 30 minutos, o dashboard envia via WhatsApp um resumo como:

```
📊 Resumo dos Apps
📅 13/04/2026, 14:30:00
━━━━━━━━━━━━━━━━━━━━━━━━━
✅ 15/17 online | ❌ OFFLINE: app-x, app-y

🟢 api-weduu — 85MB — up 12h30m
🟢 erp-cini — 120MB — up 5h15m ⚠️ 2 restart(s)
🔴 app-x
...
```

## 📡 Endpoints da API

### Processos PM2

| Método | Rota | Descrição |
|---|---|---|
| `GET` | `/api/apps` | Lista todos os processos PM2 (status, CPU, memória, porta, git) |
| `POST` | `/api/apps/:name/:action` | Ação em um app: `start`, `stop`, `restart` |
| `POST` | `/api/all/:action` | Ação em todos os apps: `stop`, `restart` |

### Logs

| Método | Rota | Descrição |
|---|---|---|
| `GET` | `/api/apps/:name/logs` | SSE — streaming de logs ao vivo do bus PM2 |
| `GET` | `/api/apps/:name/logfiles` | Lista arquivos de log físicos (.log) do app e PM2 |

### Git & Deploy

| Método | Rota | Descrição |
|---|---|---|
| `GET` | `/api/apps/:name/git` | Info do git: branch, commit atual, commits pendentes, últimos 10 commits |
| `POST` | `/api/apps/:name/pull` | Executa `git pull` no diretório do app |
| `POST` | `/api/deploy/:name` | Deploy completo: git pull + npm install + pm2 restart |
| `POST` | `/api/deploy-all` | Deploy de todos os apps (exceto log-watcher e cini-dashboard) |

### Histórico

| Método | Rota | Descrição |
|---|---|---|
| `GET` | `/api/history/stream` | SSE — streaming de histórico de deploys |

### Registro de Apps

O dashboard mantém um registro fixo (`APP_REGISTRY`) que mapeia o nome PM2 de cada app ao seu diretório no servidor, permitindo operações de git e leitura de logs:

```javascript
'api-weduu':       'C:/Projetos/API_Weduu',
'erp-cini':        'E:/Projetos/Gestao_Portaria/erp_cini',
'central-notificacoes': 'E:/Projetos/Central-Notificacoes/CentralNotificacoes',
// ... e mais 16 apps
```

## 🗄️ Banco de Dados

**SQL Server** via mssql — banco `dw`

| Tabela | Uso |
|---|---|
| `FATO_FILA_NOTIFICACOES` | Insere notificações de deploy (sucesso/falha) e resumos periódicos |

> As notificações WhatsApp são processadas pela **Central de Notificações**.

## 🔗 Integrações

| Sistema | Tipo | Descrição |
|---|---|---|
| **PM2 API** | API nativa | Lista processos, restart, stop, start, bus de logs |
| **Git** | Comando sistema | `git fetch`, `git pull`, `git log`, `git rev-parse` |
| **Central de Notificações** | Via fila DB | Processa notificações de deploy e resumos via `FATO_FILA_NOTIFICACOES` |
| **npm** | Comando sistema | `npm install --omit=dev` durante deploys |

## ⚙️ Variáveis de Ambiente

| Variável | Descrição |
|---|---|
| `DASHBOARD_PORT` | Porta do servidor (padrão: `9999`) |

**Configurações internas (hardcoded):**

| Constante | Valor | Descrição |
|---|---|---|
| `WPP_DEST` | `554188529918` | Número WhatsApp que recebe notificações de deploy |
| `APP_REGISTRY` | Objeto | Mapeamento nome PM2 → diretório do projeto |
| `DEPLOY_EXCLUDE` | `log-watcher, cini-dashboard` | Apps excluídos do deploy-all |
| `LOG_MAX` | `300` | Máximo de linhas de log em buffer por app |
| `KNOWN_PORTS` | Objeto | Portas fixas de apps conhecidos |

**Configuração do banco de dados:**

| Campo | Valor |
|---|---|
| `server` | `localhost` |
| `database` | `dw` |
| `user` | `cini.tracking` |

## 🚀 Como Rodar

```bash
# 1. Instalar dependências
cd dashboard
npm install

# 2. Rodar em desenvolvimento
node server.js

# 3. Rodar com PM2 (produção)
pm2 start server.js --name cini-dashboard --cwd E:/Projetos/monitor/dashboard

# 4. Acessar no navegador
# http://localhost:9999
```

### Pré-requisitos
- Node.js 18+
- PM2 instalado globalmente (`npm install -g pm2`)
- SQL Server acessível com a tabela `FATO_FILA_NOTIFICACOES`
- Git instalado e configurado nos diretórios dos apps
- Apps PM2 rodando para serem gerenciados
- Central de Notificações rodando para processar alertas WhatsApp

### Interface Web

O frontend é servido como arquivos estáticos da pasta `public/`. Acesse `http://servidor:9999` para visualizar o dashboard completo com:
- Lista de processos com indicadores de status em tempo real
- Streaming de logs ao vivo (SSE) por app
- Botões de controle (restart/stop/start/deploy)
- Informações de git (branch, commits pendentes)
- Histórico de deploys com status de sucesso/falha
