# Cloudflare Code Review Agent

An automated GitHub pull-request reviewer that runs entirely on Cloudflare's free tier: Workers, SQLite Durable Objects, and Workers AI. Every PR passes through deterministic security checks, a [Clef](https://developers.cloudflare.com/workers-ai/models/clef-flash/) triage gate, and a multi-model review committee. The result is posted back to GitHub as a review with inline, one-click **Commit suggestion** fixes.

Forked from [Clawbuilders/cloudflare-code-reviewer](https://github.com/Clawbuilders/cloudflare-code-reviewer), built for [ClawBuilders](https://clawbuilder.club) S1:E5 — [Deploy AI Agents with Cloudflare](https://clawbuilder.club/events/s1/ep5/deploy-ai-agents-with-cloudflare).

**See it working** on [kravchuk-ivan/cf-review-demo](https://github.com/kravchuk-ivan/cf-review-demo/pulls):

| PR | What the agent did |
|---|---|
| [#1 Docs-only change](https://github.com/kravchuk-ivan/cf-review-demo/pull/1) | Clef classified it `docs_or_config` and skipped the expensive models. |
| [#2 Add lodash](https://github.com/kravchuk-ivan/cf-review-demo/pull/2) | Live OSV.dev lookup found 6 GHSA advisories; deps.dev flagged low OpenSSF Scorecard checks. |
| [#3 Add export endpoint](https://github.com/kravchuk-ivan/cf-review-demo/pull/3) | Flagged command injection and path traversal, with a one-click fix on the vulnerable lines. |

---

## What's different from upstream

- **Clef triage instead of Jev.** The triage gate calls `@cf/cloudflare/clef-flash`, Cloudflare's first-party decision model. Upstream used `typesafe/jev`, which is billed through AI Gateway credits and fails on a free account with `2021: Insufficient AI Gateway credits`.
- **Inline one-click suggestions.** Code-quality findings are posted through the Pull Request Reviews API, anchored to the exact diff lines, so GitHub renders a **Commit suggestion** button. Suggestion ranges are re-aligned against the real file before posting, so committing one never duplicates or breaks code. Suggestions that only repeat existing code are dropped.
- **Cleaner summaries.** The lead arbiter outputs a one-line verdict plus one badged bullet per finding, instead of restating its own checklist.
- **One-command GitHub App setup.** `npm run setup:github-app` registers the App, stores its secrets in the Worker, and redeploys.

---

## How it works

```
GitHub pull_request webhook
        │
        ▼
Cloudflare Worker  ──  verifies the HMAC signature
        │
        ▼
Durable Object (PrReviewCoordinator)
  15s debounce, so a burst of pushes produces one review
  SQLite review history per PR
        │
        ▼
Deterministic checks (no LLM)
  1  Secret scan (Gitleaks patterns)        blocks the PR on a hit
  2  OSV.dev vulnerability lookup           live API
  3  Hard-rails filter                      drops lockfiles, bundles, vendor code
  4  Policy gate (OPA-inspired)             CI/CD, auth, infra, blast radius
  7  OpenSSF Scorecard via deps.dev         live API
        │
        ▼
3.5  Clef triage gate (clef-flash)
  needs security review? needs quality review? category?
  any real finding from 2/4 forces the security pass
  neither needed → short comment, committee skipped
        │
        ▼
Committee (parallel, only the specialists Clef asked for)
  5  Security: DeepSeek-R1 Distill + full-file context for reachability
     Quality:  Qwen 2.5 Coder → JSON findings anchored to diff lines
        │
        ▼
6  Lead arbiter: Llama 3.3 70B
   dedupes, drops false alarms, checks fixes for regressions
        │
        ▼
GitHub review: summary + inline ```suggestion comments
(falls back to a plain PR comment if GitHub rejects the review)
```

### The pillars

A Worker is a V8 isolate and can't run native binaries such as `gitleaks`, `semgrep`, or `opa`. Each pillar is labeled with what actually runs:

- **REAL**: calls a live public API or model.
- **HEURISTIC**: a JavaScript re-implementation of the named project's rule ideas, not the tool itself.

| # | Pillar | Kind | What it does |
|---|---|---|---|
| 1 | [Gitleaks](https://github.com/gitleaks/gitleaks)-pattern secret scan | HEURISTIC | Regex scan for AWS, Stripe, Slack and GitHub tokens, private keys, and `.env` leaks. Blocks the PR on a hit. |
| 2 | [OSV.dev](https://osv.dev) lookup | REAL | Batch-queries new `package.json` dependencies for known CVEs and GHSAs. |
| 3 | Hard-rails file filter | HEURISTIC | Alibaba [OCR](https://github.com/alibaba/open-code-review)-style noise reduction before any tokens are spent. |
| 3.5 | [Clef](https://developers.cloudflare.com/workers-ai/models/clef-flash/) triage gate | REAL | Calibrated yes/no confidences decide which specialists run. It can add scrutiny but never suppress a deterministic finding. |
| 4 | [OPA](https://github.com/open-policy-agent/opa)-inspired policy gate | HEURISTIC | Flags CI/CD workflow, auth and infra changes, and PRs over a file-count threshold. |
| 5 | [Mantis](https://github.com/google/mantis)-style reachability | REAL context | Fetches full changed files through the Contents API so the security model judges reachability, not just the hunk. |
| 6 | [OWASP ASRH](https://github.com/OWASP/Agent-Security-Regression-Harness)-style regression gate | HEURISTIC | The arbiter is instructed to reject fixes that introduce secondary vulnerabilities. |
| 7 | [deps.dev](https://deps.dev) OpenSSF Scorecard | REAL | Resolves new dependencies to their source repo and flags low Scorecard checks. |

---

## Quickstart (Advanced Track)

Requires Node 20+, a Cloudflare account (the free plan works), and a GitHub account or org where you can create Apps.

### 1. Install and deploy

```bash
git clone https://github.com/kravchuk-ivan/cloudflare-code-reviewer.git
cd cloudflare-code-reviewer
npm install
npx wrangler login
npm run deploy
```

Note the Worker URL it prints, e.g. `https://cloudflare-code-reviewer.<you>.workers.dev`.

### 2. Create the GitHub App (one command)

```bash
npm run setup:github-app -- https://cloudflare-code-reviewer.<you>.workers.dev my-reviewer
```

This opens a browser page that registers an App through GitHub's [manifest flow](https://docs.github.com/en/apps/sharing-github-apps/registering-a-github-app-from-a-manifest), already configured with:

- Webhook pointed at `<worker>/webhook/github`, subscribed to `pull_request`.
- Permissions: Contents read, Pull requests write, Issues write, Metadata read.

After you confirm on GitHub, the script:

1. Converts the private key to PKCS#8 in memory and stores it as the `GITHUB_APP_PRIVATE_KEY` secret.
2. Stores the webhook secret as `GITHUB_WEBHOOK_SECRET`.
3. Writes the App ID into `wrangler.json`.
4. Redeploys the Worker.
5. Redirects you to the App's install page.

The key never touches disk or your terminal.

### 3. Install the App and open a PR

Install the App on the repos to review, then open a PR. The review lands in about 20–40 seconds, including the 15-second debounce.

<details>
<summary>Manual GitHub App setup (if you can't use the script)</summary>

1. Go to `github.com/organizations/<org>/settings/apps/new` (or your personal settings → Developer settings → GitHub Apps).
2. Leave "bot" out of the name. GitHub appends `[bot]` itself.
3. Delete the empty callback URL row. No user OAuth is needed.
4. **Webhook**: active, URL `<worker>/webhook/github`. Generate a secret and save it, because GitHub shows it only once.
5. **Permissions**: Contents read-only, Pull requests read & write, Issues read & write.
6. **Subscribe to events → Pull request.** Setting the permission does *not* subscribe you to the event. Without this checkbox GitHub delivers nothing, silently.
7. Create the App, note the **App ID**, and generate a private key.
8. Convert the key: `openssl pkcs8 -topk8 -nocrypt -in key.pem -out pkcs8-key.pem`
9. Set the secrets and the ID:
   ```bash
   npx wrangler secret put GITHUB_APP_PRIVATE_KEY   # paste pkcs8-key.pem
   npx wrangler secret put GITHUB_WEBHOOK_SECRET
   ```
   Then put the App ID in `wrangler.json` → `vars.GITHUB_APP_ID` and run `npm run deploy`.

Never paste private-key material into a chat or AI assistant. If it leaks, generate a new key; that invalidates the old one immediately.
</details>

---

## Configuration

| Name | Where | Purpose |
|---|---|---|
| `GITHUB_APP_ID` | `wrangler.json` vars | Your App's ID. Not secret. |
| `GITHUB_APP_PRIVATE_KEY` | Worker secret | PKCS#8 private key used to mint installation tokens. |
| `GITHUB_WEBHOOK_SECRET` | Worker secret | Verifies the `X-Hub-Signature-256` header on incoming webhooks. |
| `JEV_ESCALATION_FLOOR` | `wrangler.json` vars | Confidence threshold (default `0.5`) above which Clef sends a diff to a specialist. Lower it for more reviews, raise it to skip more. The name is kept from upstream for compatibility. |
| `AI_GATEWAY_NAME` | `wrangler.json` vars (optional) | Routes every model call through that AI Gateway for caching, logs and analytics. Create the gateway first; an unknown name causes errors. |

The installation ID isn't configured anywhere. It arrives on every webhook as `payload.installation.id`.

---

## Private repositories

- An unauthenticated fetch of `github.com/.../pull/N.diff` on a private repo returns a 404 HTML page, which parses as zero files, and the review silently stops.
- That web route also rejects App installation tokens. This Worker fetches the diff from `GET /repos/{owner}/{repo}/pulls/{n}` with `Accept: application/vnd.github.v3.diff`, which works with App tokens.
- Every GitHub call checks `response.ok` and logs failures, so problems show up in `wrangler tail` instead of disappearing.

---

## Troubleshooting

| Symptom | Check |
|---|---|
| No review, no Worker logs | App → **Advanced → Recent Deliveries**. If nothing was delivered, the App isn't subscribed to the `pull_request` event. |
| Delivery shows 401 | `GITHUB_WEBHOOK_SECRET` doesn't match the App's webhook secret. |
| Review posted, but no inline comments | GitHub rejected the inline review (e.g. the head SHA moved mid-review). The Worker falls back to a plain comment with the suggestions inlined. Push again to re-run. |
| "Clef was unavailable this run" | Clef errored and triage used the Llama fallback. Run `npx wrangler tail` to see the error. |
| Anything else | Run `npx wrangler tail --format pretty` and push an empty commit to the PR: `git commit --allow-empty -m "Re-run review" && git push`. |

---

## Starter Track

`starter/` is a separate, single-file reviewer: one stateless Worker plus Qwen 2.5 Coder. It posts as you using a personal access token instead of a GitHub App. It has its own `package.json` and `wrangler.json`.

```bash
cd starter
npm install
npm run deploy
npx wrangler secret put GITHUB_TOKEN   # classic PAT with `repo`, or fine-grained with Pull requests: RW + Contents: R
```

Then add a repo webhook (Settings → Webhooks):

- Payload URL: the Starter Worker's root URL (it accepts `POST /`).
- Content type: `application/json`.
- Events: **Pull requests**.

Optionally set a webhook secret and store it with `npx wrangler secret put GITHUB_WEBHOOK_SECRET` to enforce signature checks.

---

## Project layout

```
src/index.ts                 Advanced Track: webhook, Durable Object, pillars, committee, GitHub posting
src/github-app-auth.ts       App JWT signing + installation-token exchange (Web Crypto, no deps)
scripts/create-github-app.mjs  One-command GitHub App registration
starter/                     Starter Track (independent package)
docs/workshop-guide.md       Original workshop guide, including the OCR research and facilitator notes
wrangler.json                Worker, AI binding, Durable Object, vars
```

Local development: `npm run dev` serves on `http://localhost:8787`. Webhooks need a public URL, so test end to end against the deployed Worker.

---

## License

Apache-2.0. Original project by [ClawBuilders](https://clawbuilder.club).
