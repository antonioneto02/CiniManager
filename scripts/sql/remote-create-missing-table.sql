-- =============================================================================
-- Cria a tabela FATO_EMAILS_REJEITADOS_PROCESSADOS no banco [dw] do servidor
-- remoto (177.104.136.230), que hoje só existe no dw local.
--
-- Motivo: api-sicredi (src/services/database.js:629-655) usa essa tabela pra
-- controlar quais e-mails de cobrança rejeitados já foram reprocessados. Sem
-- ela, a app gera "Invalid object name 'dw.dbo.FATO_EMAILS_REJEITADOS_PROCESSADOS'"
-- assim que aponta pro servidor remoto (confirmado em teste real em 2026-09-16).
--
-- Rodar conectado no servidor 177.104.136.230, banco [dw], com um usuário que
-- tenha permissão de CREATE TABLE (ex.: dbo ou sysadmin).
-- =============================================================================

USE [dw];
GO

IF OBJECT_ID('dbo.FATO_EMAILS_REJEITADOS_PROCESSADOS', 'U') IS NOT NULL
BEGIN
    PRINT 'Tabela dbo.FATO_EMAILS_REJEITADOS_PROCESSADOS já existe — nada a fazer.';
END
ELSE
BEGIN
    CREATE TABLE dbo.FATO_EMAILS_REJEITADOS_PROCESSADOS (
        [ID]             int IDENTITY(1,1) NOT NULL,
        [EMAIL]          varchar(150)      NOT NULL,
        [DATA_ORIGEM]    varchar(50)       NOT NULL,
        [CODIGO_CLIENTE] varchar(10)       NULL,
        [NOME_CLIENTE]   varchar(200)      NULL,
        [DTINC]          datetime          NOT NULL DEFAULT (getdate()),
        CONSTRAINT [PK_FATO_EMAILS_REJEITADOS_PROCESSADOS] PRIMARY KEY ([ID])
    );

    CREATE UNIQUE INDEX [UX_EMAILS_REJEITADOS_EMAIL_DATA]
        ON dbo.FATO_EMAILS_REJEITADOS_PROCESSADOS ([EMAIL], [DATA_ORIGEM]);

    PRINT 'Tabela dbo.FATO_EMAILS_REJEITADOS_PROCESSADOS criada com sucesso.';
END
GO
