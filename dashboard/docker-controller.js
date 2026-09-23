const path = require('path');
const fs = require('fs');
const { execFile, spawn } = require('child_process');
const POLL_INTERVAL_MS = 15000;
const EXEC_OPTS = { windowsHide: true, maxBuffer: 16 * 1024 * 1024, timeout: 15000 };

function execFileP(cmd, args, opts) {
  return new Promise((resolve, reject) => {
    execFile(cmd, args, { ...EXEC_OPTS, ...opts }, (err, stdout, stderr) => {
      if (err) return reject(Object.assign(err, { stderr }));
      resolve(stdout);
    });
  });
}

function parseNdjson(stdout) {
  return stdout.split('\n').map(l => l.trim()).filter(Boolean).map(l => {
    try { return JSON.parse(l); } catch { return null; }
  }).filter(Boolean);
}

function parseMemToken(tok) {
  const m = String(tok || '').trim().match(/^([\d.]+)\s*([KMGT]?i?B)$/i);
  if (!m) return 0;
  const n = parseFloat(m[1]);
  const unit = m[2].toUpperCase();
  const mult = { B: 1, KIB: 1024, MIB: 1024 ** 2, GIB: 1024 ** 3, TIB: 1024 ** 4,
                 KB: 1000, MB: 1000 ** 2, GB: 1000 ** 3, TB: 1000 ** 4 }[unit] || 1;
  return Math.round(n * mult);
}

class DockerController {
  constructor() {
    this.appDirs = new Map();      
    this.containerOf = new Map();  
    this.appOfContainer = new Map();
    this.runtimeOf = new Map();    
    this.cache = new Map();         
    this.restartCounts = new Map(); 
    this.logTails = new Map();   
    this.onLog = null;     
    this.stateFile = null;
    this._pollTimer = null;
    this._eventsProc = null;
  }

  init({ appRegistry, containerOverrides = {}, stateDir, onLog }) {
    this.onLog = onLog || (() => {});
    this.stateFile = path.join(stateDir, '.restart-counts.json');
    this._loadRestartCounts();

    for (const [appName, dir] of Object.entries(appRegistry)) {
      const dirWin = dir.replace(/\//g, path.sep);
      const hasCompose = fs.existsSync(path.join(dirWin, 'docker-compose.yml'));
      if (!hasCompose) continue; 
      this.appDirs.set(appName, dirWin);
      const containerName = containerOverrides[appName] || appName;
      this.containerOf.set(appName, containerName);
      this.appOfContainer.set(containerName, appName);
      this.runtimeOf.set(appName, this._detectRuntime(dirWin));
    }

    this._startEventsStream();
    for (const appName of this.appDirs.keys()) this._startLogTail(appName);
    this._poll();
    this._pollTimer = setInterval(() => this._poll().catch(() => {}), POLL_INTERVAL_MS);
  }

  isManaged(appName) {
    return this.appDirs.has(appName);
  }

  managedAppNames() {
    return [...this.appDirs.keys()];
  }

  _detectRuntime(dirWin) {
    if (fs.existsSync(path.join(dirWin, 'supervisor-trigger.js'))) {
      return { trigger: ['C:\\nodejs\\node.exe', 'supervisor-trigger.js'] };
    }
    if (fs.existsSync(path.join(dirWin, 'supervisor_trigger.py'))) {
      return { trigger: ['C:\\Python\\python.exe', 'supervisor_trigger.py'] };
    }
    return null;
  }

  _loadRestartCounts() {
    try {
      if (fs.existsSync(this.stateFile)) {
        const raw = JSON.parse(fs.readFileSync(this.stateFile, 'utf8'));
        for (const [k, v] of Object.entries(raw)) this.restartCounts.set(k, v);
      }
    } catch {}
  }

  _saveRestartCounts() {
    try {
      const obj = Object.fromEntries(this.restartCounts.entries());
      fs.writeFileSync(this.stateFile, JSON.stringify(obj, null, 2), 'utf8');
    } catch {}
  }

  _bumpRestart(appName) {
    const prev = this.restartCounts.get(appName) || { count: 0, lastRestartAt: 0 };
    const next = { count: prev.count + 1, lastRestartAt: Date.now() };
    this.restartCounts.set(appName, next);
    this._saveRestartCounts();
  }

  resetRestartCount(appName) {
    this.restartCounts.set(appName, { count: 0, lastRestartAt: 0 });
    this._saveRestartCounts();
  }

  async _poll() {
    if (this.appDirs.size === 0) return;
    const names = [...this.containerOf.values()];
    const [psList, statsList, inspectList] = await Promise.all([
      this._dockerPs(),
      this._dockerStats(),
      this._dockerInspect(names),
    ]);
    const psByName = new Map(psList.map(p => [p.Names, p]));
    const statsByName = new Map(statsList.map(s => [s.Name, s]));
    const inspectByName = new Map(inspectList.map(i => [(i.Name || '').replace(/^\//, ''), i]));

    for (const [appName, containerName] of this.containerOf.entries()) {
      const ps = psByName.get(containerName);
      const stats = statsByName.get(containerName);
      const insp = inspectByName.get(containerName);
      const restartInfo = this.restartCounts.get(appName) || { count: 0, lastRestartAt: 0 };

      const dockerState = ps?.State || insp?.State?.Status || 'exited';
      const status = dockerState === 'running' ? 'online'
        : dockerState === 'restarting' ? 'launching'
        : 'stopped';

      const cpu = stats ? parseFloat(String(stats.CPUPerc || '0').replace('%', '')) || 0 : 0;
      const memBytes = stats ? parseMemToken(String(stats.MemUsage || '').split('/')[0]) : 0;
      const startedAt = insp?.State?.StartedAt ? Date.parse(insp.State.StartedAt) : 0;
      const pid = insp?.State?.Pid || 0;

      this.cache.set(appName, {
        pm_id: appName,
        name: appName,
        pid,
        pm2_env: {
          status,
          restart_time: restartInfo.count,
          pm_uptime: status === 'online' && startedAt ? startedAt : 0,
        },
        monit: { cpu, memory: memBytes },
      });
    }
  }

  async snapshotOnce(appRegistry, containerOverrides = {}) {
    const containerOf = new Map();
    for (const appName of Object.keys(appRegistry)) {
      const dirWin = appRegistry[appName].replace(/\//g, path.sep);
      if (!fs.existsSync(path.join(dirWin, 'docker-compose.yml'))) continue;
      containerOf.set(appName, containerOverrides[appName] || appName);
    }
    const names = [...containerOf.values()];
    const [psList, statsList, inspectList] = await Promise.all([
      this._dockerPs(),
      names.length ? execFileP('docker', ['stats', '--no-stream', '--format', '{{json .}}'], { timeout: 10000 }).then(parseNdjson).catch(() => []) : [],
      this._dockerInspect(names),
    ]);
    const psByName = new Map(psList.map(p => [p.Names, p]));
    const statsByName = new Map(statsList.map(s => [s.Name, s]));
    const inspectByName = new Map(inspectList.map(i => [(i.Name || '').replace(/^\//, ''), i]));

    const out = [];
    for (const [appName, containerName] of containerOf.entries()) {
      const ps = psByName.get(containerName);
      const stats = statsByName.get(containerName);
      const insp = inspectByName.get(containerName);
      const dockerState = ps?.State || insp?.State?.Status || 'exited';
      const status = dockerState === 'running' ? 'online' : dockerState === 'restarting' ? 'launching' : 'stopped';
      const memBytes = stats ? parseMemToken(String(stats.MemUsage || '').split('/')[0]) : 0;
      const startedAt = insp?.State?.StartedAt ? Date.parse(insp.State.StartedAt) : 0;
      out.push({
        name: appName,
        pid: insp?.State?.Pid || 0,
        status,
        pm_uptime: status === 'online' && startedAt ? startedAt : 0,
        memory: memBytes,
      });
    }
    return out;
  }

  async _dockerPs() {
    try {
      const out = await execFileP('docker', ['ps', '-a', '--format', '{{json .}}']);
      return parseNdjson(out);
    } catch { return []; }
  }

  async _dockerStats() {
    if (this.appDirs.size === 0) return [];
    try {
      const out = await execFileP('docker', ['stats', '--no-stream', '--format', '{{json .}}'], { timeout: 10000 });
      return parseNdjson(out);
    } catch { return []; }
  }

  async _dockerInspect(names) {
    if (!names.length) return [];
    try {
      const out = await execFileP('docker', ['inspect', ...names]);
      return JSON.parse(out);
    } catch { return []; }
  }

  _startEventsStream() {
    const proc = spawn('docker', ['events', '--filter', 'type=container', '--format', '{{json .}}'], { windowsHide: true });
    this._eventsProc = proc;
    let buf = '';
    proc.stdout.on('data', (chunk) => {
      buf += chunk.toString();
      const lines = buf.split('\n');
      buf = lines.pop();
      for (const line of lines) {
        if (!line.trim()) continue;
        try { this._onDockerEvent(JSON.parse(line)); } catch {}
      }
    });
    proc.on('close', () => { this._eventsProc = null; setTimeout(() => this._startEventsStream(), 5000); });
    proc.on('error', () => {});
  }

  _onDockerEvent(evt) {
    const containerName = evt?.Actor?.Attributes?.name;
    const appName = this.appOfContainer.get(containerName);
    if (!appName) return;
    if (this._onEvent) this._onEvent(appName, evt.Action, evt);
    if (evt.Action === 'die') {
      const exitCode = evt?.Actor?.Attributes?.exitCode;
      if (this._onCriticalEvent) this._onCriticalEvent(appName, exitCode && exitCode !== '0' ? 'errored' : 'exit');
    }
    this._poll().catch(() => {});
  }

  onCriticalEvent(fn) { this._onCriticalEvent = fn; }
  onEvent(fn) { this._onEvent = fn; }

  _startLogTail(appName) {
    const containerName = this.containerOf.get(appName);
    if (!containerName || this.logTails.has(appName)) return;
    const proc = spawn('docker', ['logs', '-f', '--tail', '0', containerName], { windowsHide: true });
    this.logTails.set(appName, proc);

    const handleChunk = (source) => (chunk) => {
      const text = chunk.toString();
      for (const rawLine of text.split('\n')) {
        const line = rawLine.trim();
        if (!line) continue;
        if (line.includes('[supervisor] restart pedido')) this._bumpRestart(appName);
        this.onLog(appName, source, line);
      }
    };
    proc.stdout.on('data', handleChunk('stdout'));
    proc.stderr.on('data', handleChunk('stderr'));
    proc.on('close', () => {
      this.logTails.delete(appName);
      setTimeout(() => this._startLogTail(appName), 5000);
    });
    proc.on('error', () => {});
  }

  async doAction(action, target) {
    if (target === 'all') {
      const errors = [];
      for (const appName of this.appDirs.keys()) {
        try { await this.doAction(action, appName); } catch (e) { errors.push(`${appName}: ${e.message}`); }
      }
      if (errors.length) throw new Error(errors.join('; '));
      return;
    }

    if (!this.isManaged(target)) throw new Error(`App "${target}" não é um container Docker gerenciado`);
    const dir = this.appDirs.get(target);
    const containerName = this.containerOf.get(target);

    if (action === 'reset') {
      this.resetRestartCount(target);
      return;
    }
    if (action === 'stop') {
      await execFileP('docker', ['compose', 'stop'], { cwd: dir, timeout: 60000 });
      await this._poll();
      return;
    }
    if (action === 'start') {
      await execFileP('docker', ['compose', 'up', '-d'], { cwd: dir, timeout: 180000 });
      await this._poll();
      return;
    }
    if (action === 'restart') {
      const runtime = this.runtimeOf.get(target);
      const ps = (await this._dockerPs()).find(p => p.Names === containerName);
      const running = ps?.State === 'running';
      if (running && runtime) {
        try {
          await execFileP('docker', ['exec', containerName, ...runtime.trigger], { timeout: 15000 });
        } catch (e) {
          await new Promise(r => setTimeout(r, 2000));
          await execFileP('docker', ['exec', containerName, ...runtime.trigger], { timeout: 15000 });
        }
      } else if (running) {
        // docker restart e uma unica chamada atomica processada pelo daemon:
        // sobrevive mesmo se o processo cliente (rodando dentro do proprio
        // container, caso do cini-dashboard se reiniciando) morrer no meio.
        // "docker compose up -d" e multi-etapa (parar/remover/criar/iniciar)
        // orquestrado pelo cliente e trava pela metade nesse cenario.
        await execFileP('docker', ['restart', containerName], { timeout: 60000 });
      } else {
        await execFileP('docker', ['compose', 'up', '-d'], { cwd: dir, timeout: 180000 });
      }
      await this._poll();
      return;
    }
    throw new Error(`Ação desconhecida: ${action}`);
  }

  async rebuild(appName, { build } = {}) {
    if (!this.isManaged(appName)) throw new Error(`App "${appName}" não é um container Docker gerenciado`);
    const dir = this.appDirs.get(appName);
    const args = ['compose', 'up', '-d'];
    if (build) args.push('--build');
    await execFileP('docker', args, { cwd: dir, timeout: 20 * 60 * 1000 });
    await this._poll();
  }

  list() {
    return [...this.cache.values()];
  }

  async recentLog(appName, lines = 10) {
    const containerName = this.containerOf.get(appName);
    if (!containerName) return '';
    try {
      const out = await execFileP('docker', ['logs', '--tail', String(lines), containerName], { timeout: 8000 });
      return out.trim();
    } catch { return ''; }
  }
}

module.exports = new DockerController();
