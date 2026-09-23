FROM mcr.microsoft.com/windows/servercore:ltsc2022

ENV NODE_VERSION=22.23.2
SHELL ["powershell", "-Command", "$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue';"]

# Node, e PATH com Node + CLI do Docker + Git (esses dois sao montados do
# host via volume no docker-compose.yml, nao instalados aqui: o dashboard
# precisa deles pra controlar os containers das outras apps e pra git pull).
RUN Invoke-WebRequest -Uri "https://nodejs.org/dist/v$env:NODE_VERSION/node-v$env:NODE_VERSION-win-x64.zip" -OutFile C:\node.zip ; \
    Expand-Archive C:\node.zip -DestinationPath C:\ ; \
    Rename-Item "C:\node-v$env:NODE_VERSION-win-x64" C:\nodejs ; \
    Remove-Item C:\node.zip ; \
    setx /M PATH ('C:\nodejs;C:\Program Files\docker;C:\Program Files\docker\cli-plugins;C:\Program Files\Git\cmd;' + $env:PATH)

# Sem COPY/npm ci: o codigo (com node_modules ja instalado) e todo o
# C:\Projetos e montado como volume em runtime — precisa disso porque o
# dashboard le/escreve arquivos em TODAS as pastas de app (logs, git pull
# do auto-deploy, etc.), nao so na propria pasta.
WORKDIR C:\\Projetos\\CiniManager\\dashboard
EXPOSE 9999
CMD ["C:\\nodejs\\node.exe", "server.js"]
