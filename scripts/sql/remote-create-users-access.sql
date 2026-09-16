-- =============================================================================
-- Mapeamento de usuários/acesso por banco no servidor remoto (177.104.136.230).
--
-- Todos os logins abaixo JÁ EXISTEM no servidor remoto e já foram testados com
-- sucesso em 2026-09-16 (autenticação + SELECT) contra os bancos listados como
-- "já OK". Este script serve como:
--   1) Referência de qual app usa qual login/banco (documentação).
--   2) Script idempotente pra recriar o mapeamento usuário-por-banco caso o
--      servidor remoto precise ser reconstruído/restaurado do zero.
--
-- Não cria LOGIN (nível de servidor) — só o USER (nível de banco) e os roles.
-- Se algum login realmente não existir no servidor de destino, crie primeiro:
--   CREATE LOGIN [nome.login] WITH PASSWORD = 'a senha que está no .env da app';
--
-- Rodar cada bloco conectado no banco correspondente (USE [banco]; GO).
-- =============================================================================

-- Procedure auxiliar (idempotente): cria o USER se não existir e garante os
-- roles de leitura/escrita. Rode este bloco uma vez em [master] ou em cada
-- banco antes dos blocos abaixo (repetido em cada USE por simplicidade).
-- =============================================================================


-- ── dw ───────────────────────────────────────────────────────────────────
-- Usado por: PortalConsultasCini, webhook-whatsapp, PortalRNC, PortalAcoes,
-- KanbanEntregas, GestaoImportacaoPedidos, portalApi, LP-Negocios, Cini-Leads,
-- PortalVagasRH, PortalTelevendas, SolicitacaoFachada, coleta-SAC,
-- whatsapp-bot, WhatsAppMotoristas, Central-Notificacoes (Python), cini-dashboard,
-- Hub_Cini, WhatsAppWebNode, PortalConsultasStreamlit, AssistenteIA,
-- wf-cini, API_Sicredi, erp-cini, cini-dashboard (GROUPS_DB_CFG)
USE [dw];
GO
DECLARE @logins TABLE (login_name sysname);
INSERT INTO @logins VALUES
    ('portal.consultas'),   -- já OK (testado)
    ('cini.tracking'),      -- já OK (testado)
    ('cini.pix'),           -- já OK (testado)
    ('plataforma.cargas'),  -- já OK (testado)
    ('antonio.neto'),       -- já OK (testado)
    ('gestao.portaria');    -- já OK (testado)
DECLARE @login sysname;
DECLARE cur CURSOR FOR SELECT login_name FROM @logins;
OPEN cur; FETCH NEXT FROM cur INTO @login;
WHILE @@FETCH_STATUS = 0
BEGIN
    IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = @login)
        EXEC('CREATE USER [' + @login + '] FOR LOGIN [' + @login + ']');
    EXEC('ALTER ROLE db_datareader ADD MEMBER [' + @login + ']');
    EXEC('ALTER ROLE db_datawriter ADD MEMBER [' + @login + ']');
    FETCH NEXT FROM cur INTO @login;
END
CLOSE cur; DEALLOCATE cur;
GO


-- ── p2510 (era p11_prod) ─────────────────────────────────────────────────
-- Usado por: webhook-whatsapp, api-sicredi, KanbanEntregas,
-- GestaoImportacaoPedidos, portal-consultas, whatsapp-motoristas, portal-api,
-- api-weduu, cini-pricing, erp-cini, portal-rnc, portal-acoes, notificador-pix,
-- central-notificacoes, portal-vagas-rh, assistente-ia, wf-cini
USE [p2510];
GO
DECLARE @logins TABLE (login_name sysname);
INSERT INTO @logins VALUES
    ('portal.consultas'),   -- já OK (testado — bloqueador original resolvido)
    ('cini.tracking'),      -- já OK (testado)
    ('antonio.neto'),       -- já OK (testado)
    ('weduu'),              -- já OK (testado)
    ('pricing'),            -- já OK (testado)
    ('gestao.portaria');    -- já OK (testado)
DECLARE @login sysname;
DECLARE cur CURSOR FOR SELECT login_name FROM @logins;
OPEN cur; FETCH NEXT FROM cur INTO @login;
WHILE @@FETCH_STATUS = 0
BEGIN
    IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = @login)
        EXEC('CREATE USER [' + @login + '] FOR LOGIN [' + @login + ']');
    EXEC('ALTER ROLE db_datareader ADD MEMBER [' + @login + ']');
    EXEC('ALTER ROLE db_datawriter ADD MEMBER [' + @login + ']');
    FETCH NEXT FROM cur INTO @login;
END
CLOSE cur; DEALLOCATE cur;
GO


-- ── portal_consultas ─────────────────────────────────────────────────────
-- Usado por: PortalConsultasCini, PortalRNC, PortalAcoes, KanbanEntregas,
-- LP-Negocios, Cini-Leads, SolicitacaoFachada
USE [portal_consultas];
GO
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = 'portal.consultas')
    CREATE USER [portal.consultas] FOR LOGIN [portal.consultas];
ALTER ROLE db_datareader ADD MEMBER [portal.consultas];  -- já OK (testado)
ALTER ROLE db_datawriter ADD MEMBER [portal.consultas];
GO


-- ── rnc ──────────────────────────────────────────────────────────────────
-- Usado por: PortalRNC
USE [rnc];
GO
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = 'portal.consultas')
    CREATE USER [portal.consultas] FOR LOGIN [portal.consultas];
ALTER ROLE db_datareader ADD MEMBER [portal.consultas];  -- já OK (testado)
ALTER ROLE db_datawriter ADD MEMBER [portal.consultas];
GO


-- ── intranet_cini ────────────────────────────────────────────────────────
-- Usado por: PortalIntranetCini
USE [intranet_cini];
GO
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = 'intranet.cini')
    CREATE USER [intranet.cini] FOR LOGIN [intranet.cini];
ALTER ROLE db_datareader ADD MEMBER [intranet.cini];  -- já OK (testado)
ALTER ROLE db_datawriter ADD MEMBER [intranet.cini];
GO


-- ── central_tarefas ──────────────────────────────────────────────────────
-- Usado por: Central_Tarefas
USE [central_tarefas];
GO
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = 'central_tarefas')
    CREATE USER [central_tarefas] FOR LOGIN [central_tarefas];
ALTER ROLE db_datareader ADD MEMBER [central_tarefas];  -- já OK (testado)
ALTER ROLE db_datawriter ADD MEMBER [central_tarefas];
GO


-- ── weduu ────────────────────────────────────────────────────────────────
-- Usado por: API_Weduu
USE [weduu];
GO
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = 'weduu')
    CREATE USER [weduu] FOR LOGIN [weduu];
ALTER ROLE db_datareader ADD MEMBER [weduu];  -- já OK (testado)
ALTER ROLE db_datawriter ADD MEMBER [weduu];
GO


-- ── pricing ──────────────────────────────────────────────────────────────
-- Usado por: Cini-Pricing
USE [pricing];
GO
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = 'pricing')
    CREATE USER [pricing] FOR LOGIN [pricing];
ALTER ROLE db_datareader ADD MEMBER [pricing];  -- já OK (testado)
ALTER ROLE db_datawriter ADD MEMBER [pricing];
GO


-- ── portal_rh ────────────────────────────────────────────────────────────
-- Usado por: PortalVagasRH (DB_DATABASE, não testado diretamente — mesmo
-- login portal.consultas)
USE [portal_rh];
GO
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = 'portal.consultas')
    CREATE USER [portal.consultas] FOR LOGIN [portal.consultas];
ALTER ROLE db_datareader ADD MEMBER [portal.consultas];
ALTER ROLE db_datawriter ADD MEMBER [portal.consultas];
GO

-- =============================================================================
-- Observação: todos os "já OK (testado)" acima foram confirmados por conexão
-- real em 2026-09-16 (SELECT 1). Os blocos sem essa marcação (portal_rh) não
-- foram testados ao vivo porque a app correspondente ainda não foi ligada no
-- servidor remoto — o script já deixa o acesso pronto preventivamente.
-- =============================================================================
