'use strict';
// Credential helper do git usado pelo CiniManager: entrega o PAT do .env
// (GITHUB_TOKEN_<OWNER> ou GITHUB_TOKEN) só para github.com, sem gravar o
// token na URL do remote (.git/config). Protocolo: git-credential(1).
if (process.argv[2] !== 'get') process.exit(0);

let input = '';
process.stdin.on('data', d => { input += d; });
process.stdin.on('end', () => {
  const req = {};
  for (const line of input.split(/\r?\n/)) {
    const i = line.indexOf('=');
    if (i > 0) req[line.slice(0, i)] = line.slice(i + 1);
  }
  if (req.protocol !== 'https' || req.host !== 'github.com') return;
  const owner = (req.path || '').split('/')[0];
  const token = (owner && process.env[`GITHUB_TOKEN_${owner.toUpperCase()}`]) || process.env.GITHUB_TOKEN;
  if (!token) return;
  process.stdout.write(`username=oauth2\npassword=${token}\n`);
});
