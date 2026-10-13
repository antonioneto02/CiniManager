let d = "";
process.stdin.on("data", c => d += c);
process.stdin.on("end", () => {
    if (d.charCodeAt(0) === 0xFEFF) d = d.slice(1); // remove BOM UTF-8, se vier
    const apps = JSON.parse(d);
    const out = apps.map(a => ({
        name: a.name,
        pid: a.pid,
        status: a.pm2_env ? a.pm2_env.status : null,
        cwd: a.pm2_env ? (a.pm2_env.pm_cwd || a.pm2_env.cwd) : null,
        pm_uptime: a.pm2_env ? a.pm2_env.pm_uptime : null,
        memory: a.monit ? a.monit.memory : null
    }));
    process.stdout.write(JSON.stringify(out));
});
