# 👁️ Log Watcher — Monitor de Logs PM2

> Daemon de monitoramento que observa logs de todos os apps PM2 em tempo real, detecta erros e envia alertas via WhatsApp.

## 📋 Sobre o Projeto

O **Log Watcher** é um processo de background que se conecta ao **bus de logs do PM2** e monitora continuamente a saída de todos os aplicativos gerenciados. Quando detecta padrões de erro (via regex), processos caindo ou uso excessivo de recursos do servidor, ele **envia alertas instantâneos via WhatsApp** através da fila de notificações.

O problema que resolve é simples: **ninguém fica olhando logs de servidor 24h por dia**. O Log Watcher faz isso automaticamente e avisa quando algo dá errado — seja um erro de aplicação, um processo que caiu ou o disco ficando cheio.

## 🛠️ Tecnologias

| Tecnologia | Uso |
|---|---|
| **Node.js** | Runtime principal |
| **PM2 API** | Conexão ao bus de logs e monitoramento de processos |
| **mssql** | Driver direto para SQL Server |
| **crypto** | Hash MD5 para deduplicação de alertas |
| **child_process** | Execução de comandos do sistema (wmic para disco) |
| **Porta** | Nenhuma (processo em background) |

## 🔧 Como Funciona

### 📊 Monitoramento de Logs

```
1. 🔌 Conecta-se ao bus de logs do PM2 (pm2.launchBus)
2. 👂 Escuta eventos:
   ├── log:out  → Linhas de stdout de todos os apps
   ├── process:exception → Exceções não tratadas
   └── process:event → Eventos de ciclo de vida (exit, stop, online, restart overlimit)
3. 🔍 Para cada linha de log, aplica filtros:
   ├── Ignora apps da lista IGNORE_APPS (pm2-logrotate, log-watcher, cini-dashboard)
   ├── Verifica SAFE_PATTERNS primeiro (logs normais de acesso, INFO, DEBUG)
   └── Testa contra ERROR_PATTERNS (error, exception, failed, TypeError, ECONNREFUSED, etc.)
4. 🔑 Aplica deduplicação (hash MD5 + janela de 60s) para não enviar o mesmo erro repetido
5. 📤 Insere alerta na FATO_FILA_NOTIFICACOES com status PENDENTE
```

### 🔄 Monitoramento de Processos

```
Processo CAI (exit/stop/error)
  → Primeira vez: envia 🚨 "Processo caiu!" + nome + restarts
  → Quedas seguintes: registra no log mas NÃO envia nova notificação
  
Processo VOLTA (online)
  → Se estava marcado como "down": envia ✅ "Processo recuperado"

Restart overlimit (loop de crash)
  → Envia 🔥 "Loop de crash!" — PM2 parou de reiniciar
```

### 💻 Monitoramento de Recursos do Servidor

| Recurso | Limite | Intervalo | Comportamento |
|---|---|---|---|
| **CPU por processo** | > 85% | 2 minutos | Alerta após 2 verificações consecutivas acima do limite |
| **Memória por processo** | > 500 MB | 2 minutos | Idem CPU |
| **Disco C: e E:** | > 85% uso | 10 minutos | Alerta com deduplicação de 1 hora |

## 📡 Funcionalidades

| Funcionalidade | Descrição |
|---|---|
| 🔴 Detecção de erros em stdout | Regex patterns para error, exception, failed, TypeError, ECONNREFUSED, etc. |
| 🟡 Monitoramento de stderr | Desabilitado (Python/Flask envia access logs no stderr, gerando falsos positivos) |
| 🚨 Alerta de processo caindo | Notifica quando um app PM2 cai pela primeira vez |
| ✅ Alerta de recuperação | Notifica quando um app se recupera após queda |
| 🔥 Detecção de loop de crash | Detecta quando PM2 para de reiniciar um app |
| 💻 Monitor de CPU/Memória | Alerta quando processos individuais excedem limites |
| 💿 Monitor de disco | Alerta quando drives C: ou E: excedem 85% de uso |
| 🔑 Deduplicação | Evita alertas repetidos usando hash MD5 + janela temporal |
| 🛡️ SAFE_PATTERNS | Filtra falsos positivos (logs de acesso HTTP, INFO, DEBUG) |

### Padrões de Erro Detectados

```
/error/i, /exception/i, /failed/i
/TypeError|ReferenceError|SyntaxError|RangeError|URIError/
/ECONNREFUSED|ETIMEDOUT|ENOTFOUND|ECONNRESET|EPIPE/
/unhandledRejection|uncaughtException/i
/4xx|5xx.*error|fail/
/ERRO/, /FALHA/i
```

### Padrões Seguros (ignorados)

```
[INFO], [DEBUG], [TRACE], logs de acesso HTTP,
"GET /...", "POST /...", Bad HTTP/0.9 request, etc.
```

## 🗄️ Banco de Dados

**SQL Server** via mssql — banco `dw`

| Tabela | Uso |
|---|---|
| `FATO_FILA_NOTIFICACOES` | Insere alertas com tipo `texto`, status `PENDENTE`, destinatário fixo |

> Os alertas são processados pela **Central de Notificações**, que lê a fila e envia via WhatsApp.

## 🔗 Integrações

| Sistema | Tipo | Descrição |
|---|---|---|
| **PM2** | API nativa | Conexão ao bus de logs e listagem de processos |
| **Central de Notificações** | Via fila DB | Processa os alertas inseridos em `FATO_FILA_NOTIFICACOES` |
| **Windows (wmic)** | Comando sistema | Verificação de uso de disco via `wmic logicaldisk` |

## ⚙️ Variáveis de Ambiente / Configuração

As configurações estão **hardcoded** no arquivo `log-watcher.js`:

| Constante | Valor | Descrição |
|---|---|---|
| `DESTINATARIO` | `554188529918` | Número WhatsApp que recebe os alertas |
| `DEDUP_WINDOW` | `60000` (60s) | Janela de deduplicação de alertas |
| `CPU_LIMIT_PCT` | `85` | Limite de CPU por processo (%) |
| `MEM_LIMIT_MB` | `500` | Limite de memória por processo (MB) |
| `DISK_LIMIT_PCT` | `85` | Limite de uso de disco (%) |
| `DRIVES_TO_CHECK` | `['C:', 'E:']` | Drives monitorados |
| `IGNORE_APPS` | `pm2-logrotate, log-watcher, cini-dashboard` | Apps ignorados no monitoramento |

**Configuração do banco de dados:**

| Campo | Valor |
|---|---|
| `server` | `localhost` |
| `database` | `dw` |
| `user` | `cini.tracking` |

## 🚀 Como Rodar

```bash
# 1. Instalar dependências
npm install

# 2. Rodar em desenvolvimento
node log-watcher.js

# 3. Rodar com PM2 (produção)
pm2 start log-watcher.js --name log-watcher
```

### Pré-requisitos
- Node.js 18+
- PM2 instalado globalmente (`npm install -g pm2`)
- SQL Server acessível com a tabela `FATO_FILA_NOTIFICACOES`
- Apps PM2 rodando para serem monitorados
- Central de Notificações rodando para processar os alertas

### Intervalos de Verificação

| Verificação | Intervalo | Início |
|---|---|---|
| Logs (bus PM2) | Tempo real | Imediato |
| CPU / Memória | 2 minutos | 30 segundos após start |
| Disco | 10 minutos | 60 segundos após start |
