'use strict';
// Controlador para servidores que rodam os apps no PM2 (CINI_RUNTIME=pm2 no .env do dashboard).
// Mesma interface do docker-controller.js, para o server.js não precisar saber qual dos dois está em uso.
// Usa o pm2 da linha de comando (o mesmo do daemon), não a API do node_modules, que pode ser de outra versão.
const path = require('path');
const fs = require('fs');
const { execFile, execFileSync, spawn } = require('child_process');

const POLL_INTERVAL_MS = 15000;
const EXEC_OPTS = { windowsHide: true, maxBuffer: 64 * 1024 * 1024, timeout: 60000 };

function pm2Bin() {
  if (process.env.PM2_BIN && fs.existsSync(process.env.PM2_BIN)) return process.env.PM2_BIN;
  const candidatos = [path.join(process.env.APPDATA || '', 'npm', 'node_modules', 'pm2', 'bin', 'pm2')];
  try {
    const raizGlobal = execFileSync(process.platform === 'win32' ? 'npm.cmd' : 'npm', ['root', '-g'],
      { encoding: 'utf8', windowsHide: true, timeout: 20000, shell: process.platform === 'win32' }).trim();
    candidatos.push(path.join(raizGlobal, 'pm2', 'bin', 'pm2'));
  } catch {}
  const achado = candidatos.find(c => c && fs.existsSync(c));
  if (!achado) throw new Error('pm2 global não encontrado (defina PM2_BIN no .env do dashboard).');
  return achado;
}

class Pm2Controller {
  constructor() {
    this.runtime = 'pm2';
    this.bin = null;
    this.processos = new Map();     // nome -> item no formato da lista do dashboard
    this.containerOf = new Map();   // sem containers no PM2; mantido pela interface
    this.restartCounts = new Map(); // nome -> { count, lastRestartAt }
    this.onLog = null;
    this._onEvent = null;
    this._onCriticalEvent = null;
    this._pollTimer = null;
  }

  _pm2(args, opts = {}) {
    return new Promise((resolve, reject) => {
      execFile(process.execPath, [this.bin, ...args], { ...EXEC_OPTS, ...opts }, (err, stdout, stderr) => {
        if (err) return reject(Object.assign(err, { stderr }));
        resolve(stdout);
      });
    });
  }

  _jlistSync() {
    return JSON.parse(execFileSync(process.execPath, [this.bin, 'jlist'], { ...EXEC_OPTS, encoding: 'utf8' }));
  }

  // As pastas do app-registry são as do servidor Docker (C:/Projetos/...). Aqui valem as que o PM2 usa.
  init({ appRegistry, onLog }) {
    this.onLog = onLog || (() => {});
    this.bin = pm2Bin();
    try {
      const lista = this._jlistSync();
      for (const p of lista) {
        if (p.name.startsWith('pm2-') || !p.pm2_env?.pm_cwd) continue;
        appRegistry[p.name] = p.pm2_env.pm_cwd.replace(/\\/g, '/');
      }
      this._aplicar(lista);
    } catch (e) {
      console.error('[pm2-controller] não consegui ler o pm2 jlist na inicialização:', e.message);
    }
    this._startLogStream();
    this._pollTimer = setInterval(() => this._poll().catch(() => {}), POLL_INTERVAL_MS);
  }

  // Um único "pm2 logs --json" alimenta o buffer de logs de todos os apps (detecção de erros do dashboard).
  _startLogStream() {
    const proc = spawn(process.execPath, [this.bin, 'logs', '--json', '--lines', '0'], { windowsHide: true });
    let buf = '';
    proc.stdout.on('data', (chunk) => {
      buf += chunk.toString();
      const linhas = buf.split('\n');
      buf = linhas.pop();
      for (const linha of linhas) {
        if (!linha.trim()) continue;
        let evt;
        try { evt = JSON.parse(linha); } catch { continue; }
        if (!evt.app_name || evt.app_name.startsWith('pm2-')) continue;
        for (const texto of String(evt.message || '').split('\n')) {
          if (texto.trim()) this.onLog(evt.app_name, evt.type === 'err' ? 'stderr' : 'stdout', texto.trim());
        }
      }
    });
    proc.on('close', () => setTimeout(() => this._startLogStream(), 5000));
    proc.on('error', () => {});
  }

  async _poll() {
    this._aplicar(JSON.parse(await this._pm2(['jlist'])));
  }

  _aplicar(lista) {
    const vistos = new Set();
    for (const p of lista) {
      if (p.name.startsWith('pm2-')) continue;
      vistos.add(p.name);
      const env = p.pm2_env || {};
      const status = env.status === 'online' ? 'online'
        : env.status === 'launching' ? 'launching'
        : env.status === 'errored' ? 'errored'
        : 'stopped';
      const anterior = this.processos.get(p.name);
      const restarts = env.restart_time || 0;
      const rc = this.restartCounts.get(p.name);
      if (!rc || restarts > rc.count) this.restartCounts.set(p.name, { count: restarts, lastRestartAt: rc ? Date.now() : (env.pm_uptime || 0) });

      this.processos.set(p.name, {
        pm_id: p.name,
        name: p.name,
        pid: p.pid || 0,
        pm2_env: { status, restart_time: restarts, pm_uptime: status === 'online' ? (env.pm_uptime || 0) : 0 },
        monit: { cpu: p.monit?.cpu || 0, memory: p.monit?.memory || 0 },
      });

      // Mesmos avisos que o docker-controller gera a partir dos eventos do Docker.
      if (anterior) {
        const antes = anterior.pm2_env.status;
        if (antes !== 'online' && status === 'online' && this._onEvent) this._onEvent(p.name, 'start', {});
        if (antes === 'online' && status !== 'online') {
          if (this._onEvent) this._onEvent(p.name, 'die', {});
          if (this._onCriticalEvent) this._onCriticalEvent(p.name, status === 'errored' ? 'errored' : 'exit');
        }
      }
    }
    for (const nome of [...this.processos.keys()]) if (!vistos.has(nome)) this.processos.delete(nome);
  }

  onCriticalEvent(fn) { this._onCriticalEvent = fn; }
  onEvent(fn) { this._onEvent = fn; }

  isManaged(appName) {
    return this.processos.has(appName);
  }

  managedAppNames() {
    return [...this.processos.keys()];
  }

  resetRestartCount(appName) {
    const prev = this.restartCounts.get(appName) || { lastRestartAt: 0 };
    this.restartCounts.set(appName, { count: 0, lastRestartAt: prev.lastRestartAt || 0 });
  }

  async doAction(action, target) {
    if (target !== 'all' && !this.isManaged(target)) throw new Error(`App "${target}" não está no PM2`);
    if (action === 'reset') {
      await this._pm2(['reset', target]);
      if (target !== 'all') this.resetRestartCount(target);
      return this._poll();
    }
    if (!['start', 'stop', 'restart'].includes(action)) throw new Error(`Ação desconhecida: ${action}`);
    // Reiniciar o próprio dashboard mataria este processo antes do pm2 terminar: dispara desacoplado.
    if (target === 'cini-dashboard' || (target === 'all' && action !== 'start')) {
      spawn(process.execPath, [this.bin, action, target], { detached: true, stdio: 'ignore', windowsHide: true }).unref();
      return;
    }
    await this._pm2([action, target, ...(action === 'restart' ? ['--update-env'] : [])], { timeout: 120000 });
    await this._poll();
  }

  // Sem imagem para reconstruir: no PM2 basta reiniciar.
  async rebuild(appName) {
    return this.doAction('restart', appName);
  }

  list() {
    return [...this.processos.values()];
  }

  async recentLog(appName, lines = 10) {
    try {
      const out = await this._pm2(['logs', appName, '--lines', String(lines), '--nostream', '--raw'], { timeout: 15000 });
      return out.trim();
    } catch { return ''; }
  }
}

module.exports = new Pm2Controller();
