// One-click GitHub App registration via the manifest flow:
// https://docs.github.com/en/apps/sharing-github-apps/registering-a-github-app-from-a-manifest
//
// Serves a local page that POSTs a pre-filled manifest to GitHub (permissions,
// pull_request event, webhook URL), then exchanges the returned code for the
// App's credentials and pipes them straight into `wrangler secret put`. The
// private key is converted PKCS#1 → PKCS#8 in memory and never printed.
//
// Usage: node scripts/create-github-app.mjs <worker-url> [app-name]

import http from 'node:http';
import crypto from 'node:crypto';
import { spawnSync, execSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';

const [workerUrl, appName = 'kravchuk-cf-reviewer'] = process.argv.slice(2);
if (!workerUrl) {
  console.error('Usage: node scripts/create-github-app.mjs <worker-url> [app-name]');
  process.exit(1);
}

const PORT = 3456;
const state = crypto.randomBytes(16).toString('hex');
const manifest = {
  name: appName,
  url: workerUrl,
  hook_attributes: { url: `${workerUrl.replace(/\/$/, '')}/webhook/github`, active: true },
  redirect_url: `http://localhost:${PORT}/callback`,
  public: false,
  default_permissions: {
    contents: 'read',
    pull_requests: 'write',
    // POST /issues/{n}/comments (pr.comments_url) needs issues:write.
    issues: 'write',
    metadata: 'read',
  },
  default_events: ['pull_request'],
};

function putSecret(name, value) {
  const res = spawnSync('npx', ['wrangler', 'secret', 'put', name], { input: value, encoding: 'utf8' });
  if (res.status !== 0) throw new Error(`wrangler secret put ${name} failed: ${res.stderr}`);
}

const escapeHtml = (s) => s.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;');

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);

  if (url.pathname === '/') {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(`<!doctype html><meta charset="utf-8"><title>Create GitHub App</title>
<form method="post" action="https://github.com/settings/apps/new?state=${state}">
  <input type="hidden" name="manifest" value="${escapeHtml(JSON.stringify(manifest))}">
  <p>Registering <b>${escapeHtml(appName)}</b> → webhook ${escapeHtml(manifest.hook_attributes.url)}</p>
  <button type="submit">Continue to GitHub</button>
</form>
<script>document.forms[0].submit()</script>`);
    return;
  }

  if (url.pathname === '/callback') {
    if (url.searchParams.get('state') !== state) {
      res.writeHead(400).end('State mismatch');
      return;
    }
    try {
      const conv = await fetch(`https://api.github.com/app-manifests/${url.searchParams.get('code')}/conversions`, {
        method: 'POST',
        headers: { Accept: 'application/vnd.github+json', 'User-Agent': 'cf-reviewer-setup' },
      });
      if (!conv.ok) throw new Error(`Manifest conversion failed: ${conv.status} ${await conv.text()}`);
      const app = await conv.json();

      const pkcs8 = crypto.createPrivateKey(app.pem).export({ type: 'pkcs8', format: 'pem' });
      putSecret('GITHUB_APP_PRIVATE_KEY', pkcs8);
      putSecret('GITHUB_WEBHOOK_SECRET', app.webhook_secret);

      const wranglerPath = new URL('../wrangler.json', import.meta.url);
      const config = JSON.parse(readFileSync(wranglerPath, 'utf8'));
      config.vars.GITHUB_APP_ID = String(app.id);
      writeFileSync(wranglerPath, JSON.stringify(config, null, 2) + '\n');
      execSync('npx wrangler deploy', { stdio: 'ignore', cwd: new URL('..', import.meta.url).pathname });

      console.log(`App created: id=${app.id} slug=${app.slug}`);
      console.log(`Install it: ${app.html_url}/installations/new`);
      res.writeHead(302, { Location: `${app.html_url}/installations/new` }).end();
    } catch (err) {
      console.error(err.message);
      res.writeHead(500).end(`Setup failed: ${err.message}`);
    }
    server.close();
    return;
  }

  res.writeHead(404).end();
});

server.listen(PORT, () => {
  console.log(`Open http://localhost:${PORT} to register the GitHub App`);
  execSync(`open http://localhost:${PORT}`);
});
