import { DurableObject } from 'cloudflare:workers';
import parseDiff from 'parse-diff';
import { resolveGitHubToken, verifyWebhookSignature, type GitHubAppEnv } from './github-app-auth';

export interface Env extends GitHubAppEnv {
  // Kept as `any` deliberately: Workers AI's typed `Ai` binding infers a
  // different, narrower output shape per model (some resolve `.run()` to a
  // plain `string` instead of `{ response: string }`), which fights the
  // uniform `.response` access used across every model call below.
  AI: any;
  PR_COORDINATOR: DurableObjectNamespace<PrReviewCoordinator>;
  GITHUB_WEBHOOK_SECRET?: string;
  AI_GATEWAY_NAME?: string;
  // Noul-probability floor above which Clef's triage call routes a diff to
  // the corresponding specialist. Lower = more cautious (runs the
  // committee more often); higher = cheaper but more likely to skip a real
  // dependency_bump/docs-only false negative. 0.5 is a starting point, not
  // a validated threshold — tune against this repo's own PR traffic.
  JEV_ESCALATION_FLOOR?: string;
}

// ── Ingress Worker ────────────────────────────────────────────────────────────
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    // Dashboard / Health Check
    if (request.method === 'GET') {
      return new Response(
        `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Cloudflare Code Review Agent (7-Pillar Security Suite)</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0a0a0a; color: #f3f4f6; margin: 0; padding: 2rem; }
    .card { max-width: 760px; margin: 3rem auto; background: #18181b; border: 1px solid #27272a; border-radius: 1rem; padding: 2.5rem; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }
    h1 { color: #fe5e1e; font-size: 1.75rem; margin-top: 0; display: flex; align-items: center; gap: 0.5rem; }
    p { color: #a1a1aa; line-height: 1.6; font-size: 0.95rem; }
    .badge { display: inline-block; background: rgba(254, 94, 30, 0.15); color: #fe5e1e; font-size: 0.75rem; font-weight: 700; padding: 0.25rem 0.6rem; border-radius: 9999px; margin-bottom: 1rem; text-transform: uppercase; letter-spacing: 0.05em; }
    .endpoint { background: #09090b; border: 1px solid #27272a; padding: 0.75rem 1rem; border-radius: 0.5rem; font-family: monospace; font-size: 0.9rem; color: #e4e4e7; margin: 1rem 0; word-break: break-all; }
    ul { padding-left: 1.25rem; color: #a1a1aa; font-size: 0.9rem; line-height: 1.8; }
    li strong { color: #f4f4f5; }
    .tag { font-size: 0.7rem; font-weight: 700; padding: 0.1rem 0.45rem; border-radius: 0.3rem; margin-left: 0.4rem; }
    .tag.real { background: rgba(34, 197, 94, 0.15); color: #4ade80; }
    .tag.heuristic { background: rgba(250, 204, 21, 0.15); color: #facc15; }
  </style>
</head>
<body>
  <div class="card">
    <div class="badge">Live on Cloudflare Edge</div>
    <h1>🤖 Cloudflare Code Review Agent</h1>
    <p>An autonomous GitHub PR review agent built on Cloudflare Workers, Durable Objects &amp; Workers AI, inspired by <strong>Alibaba open-code-review (OCR)</strong> and guarded by a <strong>7-Pillar Security Harness Suite</strong>.</p>

    <p><strong>Webhook Ingress Endpoint:</strong></p>
    <div class="endpoint">POST ${url.origin}/webhook/github</div>

    <p><strong>The 7-Pillar Security Suite:</strong> <span class="tag real">REAL</span> pillars call a live external API with no native binary required — exactly what a V8-isolate Worker can do. <span class="tag heuristic">HEURISTIC</span> pillars are lightweight, honest re-implementations of the named project's rule *ideas* in JS, not the actual binary (Workers can't exec native code without paid Sandboxes).</p>
    <ul>
      <li><strong>1. Gitleaks-pattern Secret Scan</strong><span class="tag heuristic">HEURISTIC</span> — regex/entropy rules modeled on Gitleaks' public default ruleset. Blocks the PR on hardcoded API keys, tokens, and private keys.</li>
      <li><strong>2. OSV.dev Vulnerability Lookup</strong><span class="tag real">REAL</span> — new/changed <code>package.json</code> dependencies are queried live against <a href="https://osv.dev" style="color:#fe5e1e">osv.dev</a>'s public vulnerability database.</li>
      <li><strong>3. Hard-Rails File Filter</strong><span class="tag heuristic">HEURISTIC</span> — Alibaba-OCR-style noise reduction (lockfiles, bundles, vendor code). Not a Semgrep integration; SAST-style reasoning happens in the LLM pass below.</li>
      <li><strong>3.5. Clef Triage Gate</strong><span class="tag real">REAL</span> — <a href="https://developers.cloudflare.com/workers-ai/models/clef-flash/" style="color:#fe5e1e">clef-flash</a> (Cloudflare's open-source decision model) judges whether this diff needs the security specialist, the quality specialist, both, or neither — a docs-only or dependency-bump PR skips the expensive committee entirely. Deterministic findings (OSV.dev, policy gate) always force a security pass regardless of what Clef says.</li>
      <li><strong>4. OPA-inspired Policy Gate</strong><span class="tag heuristic">HEURISTIC</span> — flags changes to CI/CD workflows, auth code, or infra config, and PRs over a blast-radius file-count threshold.</li>
      <li><strong>5. Mantis-style Reachability Check</strong><span class="tag real">REAL context, heuristic reasoning</span> — pulls full file content (not just the diff hunk) from the GitHub Contents API so the security model can judge whether a flaw is actually reachable.</li>
      <li><strong>6. OWASP-ASRH-style Regression Check</strong><span class="tag heuristic">HEURISTIC</span> — the Lead Arbiter is instructed to verify proposed fixes introduce no secondary vulnerabilities before posting.</li>
      <li><strong>7. OpenSSF Scorecard Supply-Chain Check</strong><span class="tag real">REAL</span> — new dependencies are looked up against <a href="https://deps.dev" style="color:#fe5e1e">deps.dev</a>'s OpenSSF Scorecard data (maintenance, code review practices) via its public API.</li>
    </ul>

    <p><strong>Multi-Model Reasoning Committee:</strong></p>
    <ul>
      <li><em>DeepSeek-R1 Distill</em> (Security & Exploit Analysis) + <em>Alibaba Qwen 2.5 Coder</em> (Clean Syntax & Fixes), synthesized by <em>Llama 3.3 70B</em> — all three proxied through Cloudflare AI Gateway for 24h caching.</li>
    </ul>
  </div>
</body>
</html>`,
        { headers: { 'Content-Type': 'text/html;charset=UTF-8' } }
      );
    }

    if (request.method !== 'POST') {
      return new Response('Method Not Allowed', { status: 405 });
    }

    // Read the raw body once — needed verbatim for HMAC verification, then
    // parsed from that same string (calling request.json() first would
    // consume the stream and leave nothing for the signature check).
    const rawBody = await request.text();
    const signatureValid = await verifyWebhookSignature(
      env.GITHUB_WEBHOOK_SECRET,
      rawBody,
      request.headers.get('x-hub-signature-256')
    );
    if (!signatureValid) {
      return new Response('Invalid webhook signature', { status: 401 });
    }

    let payload: any;
    try {
      payload = JSON.parse(rawBody);
    } catch {
      return new Response('Invalid JSON', { status: 400 });
    }

    // Only handle pull_request events (opened or new commits pushed)
    if (!payload.pull_request || (payload.action !== 'opened' && payload.action !== 'synchronize')) {
      return new Response('Event ignored', { status: 200 });
    }

    // Route event to a Durable Object isolated per Pull Request
    const prKey = `${payload.repository.full_name}#${payload.pull_request.number}`;
    const stub = env.PR_COORDINATOR.getByName(prKey);

    return stub.fetch(new Request('https://internal/queue-review', {
      method: 'POST',
      body: JSON.stringify(payload)
    }));
  }
};

// ── Security Harnesses ─────────────────────────────────────────────────────────

// Pillar 1: Secret & Credential Scanner (Gitleaks-pattern heuristic)
// Modeled on gitleaks' public default rule categories — this is JS regex, not
// the gitleaks binary (Workers can't exec native code without paid Sandboxes).
function scanForSecrets(diffText: string): string[] {
  const findings: string[] = [];
  const secretPatterns = [
    { name: 'GitHub Token', regex: /gh[pousr]_[A-Za-z0-9_]{36,}/g },
    { name: 'OpenAI API Key', regex: /sk-[a-zA-Z0-9]{32,}/g },
    { name: 'AWS Access Key ID', regex: /AKIA[0-9A-Z]{16}/g },
    { name: 'Slack Token', regex: /xox[baprs]-[A-Za-z0-9-]{10,}/g },
    { name: 'Slack Webhook URL', regex: /hooks\.slack\.com\/services\/T[A-Za-z0-9]+\/B[A-Za-z0-9]+\/[A-Za-z0-9]+/g },
    { name: 'Stripe API Key', regex: /(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{16,}/g },
    { name: 'Google API Key', regex: /AIza[0-9A-Za-z_-]{35}/g },
    { name: 'Twilio API Key', regex: /SK[a-f0-9]{32}/g },
    { name: 'SendGrid API Key', regex: /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/g },
    { name: 'npm Access Token', regex: /npm_[A-Za-z0-9]{36}/g },
    { name: 'Heroku API Key', regex: /[hH]eroku[a-zA-Z0-9_ .=:"'-]{0,20}\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b/g },
    { name: 'RSA/EC/PGP Private Key Block', regex: /-----BEGIN\s(?:RSA|EC|OPENSSH|PGP|DSA)?\s?PRIVATE KEY-----/g },
    { name: 'Generic Secret Assignment', regex: /(?:api[_-]?key|secret[_-]?key|private[_-]?key|access[_-]?token)\s*[:=]\s*['"][A-Za-z0-9_/+=-]{16,}['"]/gi },
  ];

  for (const { name, regex } of secretPatterns) {
    if (regex.test(diffText)) {
      findings.push(name);
    }
  }
  return findings;
}

// Pillar 2: Dependency Vulnerability Auditor — REAL osv.dev API lookup
// Extracts newly added `"name": "version"` pairs out of package.json diff
// hunks and batch-queries the public OSV.dev database (no auth required).
// Scope note: only package.json is parsed (not pnpm-lock.yaml/Cargo.lock —
// those need a real lockfile parser to do honestly); and since package.json
// pins ranges (e.g. "^4.17.15"), the caret/tilde is stripped and the base
// version is queried, which can occasionally miss a vuln patched between the
// base version and what actually gets installed. Good enough for a live
// demo; not a substitute for `npm audit` / a real CI supply-chain gate.
interface DependencyUpdate { name: string; version: string; }

function extractPackageJsonDependencyUpdates(parsedFiles: parseDiff.File[]): DependencyUpdate[] {
  const updates: DependencyUpdate[] = [];
  const depLineRegex = /^[+\s]*"([^"@][^"]*)":\s*"[\^~]?([0-9][^"]*)"/;

  for (const file of parsedFiles) {
    const filename = file.to || '';
    if (!filename.endsWith('package.json')) continue;

    for (const chunk of file.chunks) {
      for (const change of chunk.changes) {
        if (change.type !== 'add') continue;
        const match = depLineRegex.exec(change.content);
        if (match) {
          updates.push({ name: match[1], version: match[2] });
        }
      }
    }
  }
  // Bound the batch size — keeps latency and osv.dev rate limits sane for a live demo.
  return updates.slice(0, 10);
}

async function checkOsvVulnerabilities(deps: DependencyUpdate[]): Promise<string[]> {
  if (deps.length === 0) return [];

  try {
    const response = await fetch('https://api.osv.dev/v1/querybatch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        queries: deps.map((dep) => ({
          version: dep.version,
          package: { name: dep.name, ecosystem: 'npm' }
        }))
      })
    });

    if (!response.ok) return [];

    const data: any = await response.json();
    const results: string[] = [];
    (data.results || []).forEach((result: any, i: number) => {
      const vulns = result.vulns || [];
      if (vulns.length > 0) {
        const ids = vulns.map((v: any) => v.id).join(', ');
        results.push(`${deps[i].name}@${deps[i].version} — ${vulns.length} known advisor${vulns.length === 1 ? 'y' : 'ies'} (${ids})`);
      }
    });
    return results;
  } catch (err) {
    console.error('OSV lookup failed (failing open):', err);
    return [];
  }
}

// Pillar 4: Blast Radius & Policy Gate (OPA-inspired heuristic)
// A real OPA integration would compile a Rego policy to WASM
// (`opa build -t wasm`) and evaluate it with @open-policy-agent/opa-wasm —
// that's a legitimate upgrade path but needs a build step this workshop
// doesn't have time for. This is a hand-rolled stand-in for that policy.
function evaluateOpaPolicy(parsedFiles: parseDiff.File[]): string[] {
  const policyViolations: string[] = [];
  const sensitivePatterns = [
    { pattern: '.github/workflows/', description: 'CI/CD Workflow modification (Pipeline poisoning risk)' },
    { pattern: 'auth/', description: 'Core authentication/authorization middleware modification' },
    { pattern: 'wrangler.json', description: 'Cloudflare binding / infrastructure config modification' },
  ];

  for (const file of parsedFiles) {
    const filename = file.to || '';
    for (const { pattern, description } of sensitivePatterns) {
      if (filename.includes(pattern)) {
        policyViolations.push(`⚠️ Policy Warning (${description}): ${filename}`);
      }
    }
  }

  // Blast radius check: > 15 files changed in one PR
  if (parsedFiles.length > 15) {
    policyViolations.push(`⚠️ Blast Radius Warning: PR modifies ${parsedFiles.length} files. Recommended to split into smaller PRs.`);
  }

  return policyViolations;
}

// Clef Triage Gate — decides which specialist(s) actually need to run.
// clef-flash (https://developers.cloudflare.com/workers-ai/models/clef-flash/)
// is Cloudflare's first-party decision model: cheap, calibrated Noul/Choice judgments,
// not a code generator. It can't replace DeepSeek-R1 or Qwen's reasoning —
// it sits in front of them as a cascade gate, the same shape as the other
// two Episode 5 bonus tracks (clawbuilders-story-agent's redaction pass,
// web-qa-jev-agent's escalation gate): the expensive tier only runs when
// something actually needs it.
interface TriageResult {
  needsSecurity: boolean;
  needsQuality: boolean;
  category: string;
  securityNoul: number;
  qualityNoul: number;
  // Which tier actually produced this judgment — surfaced in the posted
  // comment so a degraded run is never mistaken for a normal one.
  source: 'clef' | 'fallback-model' | 'fail-open';
}

interface RawTriageAnswer {
  needsSecurity: boolean;
  needsQuality: boolean;
  category: string;
  securityNoul: number;
  qualityNoul: number;
}

// AI Gateway's Unified Billing path (active once credits are loaded) wraps
// some responses in a job-style envelope — { state: "Completed", result: {...} }
// — instead of returning the model's result directly. Peel it off if present;
// live-confirmed shape via `wrangler tail`, not assumed from docs.
function unwrapGatewayResult(response: any): any {
  return response && typeof response === 'object' && 'result' in response ? response.result : response;
}

const TRIAGE_CATEGORIES = {
  feature: 'New functionality',
  bugfix: 'Fixes broken behavior',
  refactor: 'Restructures existing code without changing behavior',
  docs_or_config: 'Documentation, comments, or non-code config only',
  dependency_bump: 'Only updates dependency versions',
  test_only: 'Only adds or modifies tests',
} as const;

async function triageWithClef(
  ai: any,
  reviewableFiles: parseDiff.File[],
  diffHunk: string,
  gatewayOpts: any
): Promise<RawTriageAnswer> {
  const response = await ai.run(
    '@cf/cloudflare/clef-flash',
    {
      model: 'clef-flash',
      state: {
        files_changed: reviewableFiles.map((f) => f.to || f.from || '').filter(Boolean),
        diff_hunk: diffHunk.slice(0, 4000),
      },
      questions: {
        needs_security_review: {
          type: 'noul',
          instructions:
            "Does this diff touch logic where a real security vulnerability (injection, auth bypass, unsafe deserialization, race condition, resource leak) is plausible? Answer no for docs-only, style-only, or test-fixture-only changes.",
        },
        needs_quality_review: {
          type: 'noul',
          instructions:
            'Would a human code reviewer likely have substantive style/correctness feedback on this diff, beyond nitpicks? Answer no for trivial or mechanical changes (dependency bumps, generated files, pure formatting).',
        },
        category: {
          type: 'choice',
          instructions: 'What kind of change is this?',
          criteria: TRIAGE_CATEGORIES,
        },
      },
    },
    gatewayOpts
  );

  const result = unwrapGatewayResult(response);

  return {
    needsSecurity: result.answers.needs_security_review.noul >= 0.5,
    needsQuality: result.answers.needs_quality_review.noul >= 0.5,
    category: result.answers.category.choice,
    securityNoul: result.answers.needs_security_review.noul,
    qualityNoul: result.answers.needs_quality_review.noul,
  };
}

// Fallback — if the Clef call fails for any reason (capacity, schema
// drift, quota), fall back to a
// first-party model already proven to work on the free tier in this exact
// pipeline (the Lead Arbiter below uses the same one) and ask it to
// approximate the same yes/no/category judgment as plain JSON. Less
// calibrated than Clef's actual probabilities, but keeps the triage gate
// functioning without a paid dependency.
async function triageWithFallbackModel(
  ai: any,
  reviewableFiles: parseDiff.File[],
  diffHunk: string,
  gatewayOpts: any
): Promise<RawTriageAnswer> {
  const response = await ai.run(
    '@cf/meta/llama-3.3-70b-instruct-fp8-fast',
    {
      messages: [
        {
          role: 'system',
          content: `You are a fast triage classifier for a code review pipeline. Given a diff, decide two yes/no questions and a category. Respond with ONLY a JSON object, no prose, no markdown fences, in exactly this shape:
{"needs_security_review": true|false, "needs_quality_review": true|false, "category": "feature"|"bugfix"|"refactor"|"docs_or_config"|"dependency_bump"|"test_only"}

needs_security_review: true if the diff touches logic where a real security vulnerability (injection, auth bypass, unsafe deserialization, race condition, resource leak) is plausible. false for docs-only, style-only, or test-fixture-only changes.
needs_quality_review: true if a human reviewer would likely have substantive style/correctness feedback beyond nitpicks. false for trivial/mechanical changes (dependency bumps, generated files, pure formatting).`,
        },
        {
          role: 'user',
          content: `Files changed: ${JSON.stringify(reviewableFiles.map((f) => f.to || f.from || '').filter(Boolean))}\n\nDiff:\n${diffHunk.slice(0, 4000)}`,
        },
      ],
    },
    gatewayOpts
  );

  const result = unwrapGatewayResult(response);
  // Depending on routing, this comes back either as Workers AI's simple
  // `{ response: "..." }` shape or an OpenAI-compatible chat-completions
  // shape (`choices[0].message.content`) — live-confirmed both occur.
  const text: string =
    typeof result?.response === 'string' ? result.response : result?.choices?.[0]?.message?.content ?? '';
  const jsonMatch = text.match(/\{[\s\S]*\}/);
  if (!jsonMatch) throw new Error(`Fallback triage model did not return parseable JSON: ${text.slice(0, 200)}`);

  const parsed = JSON.parse(jsonMatch[0]);
  if (typeof parsed.needs_security_review !== 'boolean' || typeof parsed.needs_quality_review !== 'boolean') {
    throw new Error(`Fallback triage model returned malformed JSON: ${jsonMatch[0].slice(0, 200)}`);
  }

  return {
    needsSecurity: parsed.needs_security_review,
    needsQuality: parsed.needs_quality_review,
    category: typeof parsed.category === 'string' && parsed.category in TRIAGE_CATEGORIES ? parsed.category : 'unknown',
    securityNoul: parsed.needs_security_review ? 1 : 0,
    qualityNoul: parsed.needs_quality_review ? 1 : 0,
  };
}

// Orchestrates the cascade: Clef (cheap, calibrated) → free-tier model
// fallback (cheaper still, less calibrated) → fail open (run the full
// committee) if even that errors. Never silently drops a review — the
// previous version of this gate had no fallback at all, so any Jev-layer
// failure (e.g. AI Gateway credits running out) meant the alarm's outer
// catch swallowed the error and nothing ever posted to the PR.
async function runTriage(
  ai: any,
  reviewableFiles: parseDiff.File[],
  diffHunk: string,
  policyAlerts: string[],
  vulnerabilityFindings: string[],
  escalationFloor: number,
  gatewayOpts: any
): Promise<TriageResult> {
  // Clef can only ADD scrutiny, never suppress a real deterministic finding —
  // if OSV.dev or the policy gate already flagged something concrete, the
  // security specialist runs regardless of what any triage tier says.
  const forcedBySignal = policyAlerts.length > 0 || vulnerabilityFindings.length > 0;

  const finalize = (raw: RawTriageAnswer, source: TriageResult['source']): TriageResult => ({
    needsSecurity: raw.needsSecurity || forcedBySignal,
    needsQuality: raw.needsQuality,
    category: raw.category,
    securityNoul: raw.securityNoul,
    qualityNoul: raw.qualityNoul,
    source,
  });

  try {
    const raw = await triageWithClef(ai, reviewableFiles, diffHunk, gatewayOpts);
    return finalize(
      { ...raw, needsSecurity: raw.securityNoul >= escalationFloor, needsQuality: raw.qualityNoul >= escalationFloor },
      'clef'
    );
  } catch (clefErr: any) {
    console.error('Clef triage failed, falling back to free-tier model:', clefErr?.message ?? clefErr);
  }

  try {
    const raw = await triageWithFallbackModel(ai, reviewableFiles, diffHunk, gatewayOpts);
    return finalize(raw, 'fallback-model');
  } catch (fallbackErr: any) {
    console.error('Fallback triage also failed, failing open (full committee runs):', fallbackErr?.message ?? fallbackErr);
  }

  return finalize({ needsSecurity: true, needsQuality: true, category: 'unknown', securityNoul: 1, qualityNoul: 1 }, 'fail-open');
}

// Pillar 5: Mantis-style Reachability Check — REAL context via GitHub Contents API
// The point of Google Mantis is verifying a flagged defect is actually
// reachable, not just pattern-matched. A diff hunk alone can't tell you that
// (no surrounding function, no call sites) — so this fetches the *full* file
// content for a bounded number of changed files at the PR's head commit and
// hands it to the security model alongside the diff.
async function fetchFullFileContext(
  repoFullName: string,
  headSha: string,
  filePaths: string[],
  githubToken: string | undefined
): Promise<string> {
  const [owner, repo] = repoFullName.split('/');
  const headers: Record<string, string> = {
    'User-Agent': 'Cloudflare-Code-Reviewer',
    'Accept': 'application/vnd.github.raw+json',
  };
  if (githubToken) headers['Authorization'] = `token ${githubToken}`;

  const MAX_FILES = 2;
  const MAX_CHARS_PER_FILE = 4000;
  const sections: string[] = [];

  for (const path of filePaths.slice(0, MAX_FILES)) {
    try {
      const res = await fetch(
        `https://api.github.com/repos/${owner}/${repo}/contents/${encodeURIComponent(path)}?ref=${headSha}`,
        { headers }
      );
      if (!res.ok) continue;
      const content = await res.text();
      sections.push(`--- Full file: ${path} ---\n${content.slice(0, MAX_CHARS_PER_FILE)}`);
    } catch (err) {
      console.error(`Full-file context fetch failed for ${path} (continuing without it):`, err);
    }
  }

  return sections.join('\n\n');
}

// Pillar 7: Supply-Chain Provenance — REAL OpenSSF Scorecard via deps.dev API
// For each new dependency, resolves its source repo through deps.dev's
// GetVersion endpoint, then pulls that repo's OpenSSF Scorecard checks.
// Bounded to 2 dependencies per run to keep the two-hop lookup fast.
async function checkSupplyChainScorecard(deps: DependencyUpdate[]): Promise<string[]> {
  const findings: string[] = [];

  for (const dep of deps.slice(0, 2)) {
    try {
      const versionRes = await fetch(
        `https://api.deps.dev/v3/systems/npm/packages/${encodeURIComponent(dep.name)}/versions/${encodeURIComponent(dep.version)}`
      );
      if (!versionRes.ok) continue;
      const versionData: any = await versionRes.json();

      const projectId = versionData.relatedProjects?.[0]?.projectKey?.id;
      if (!projectId) continue;

      const projectRes = await fetch(`https://api.deps.dev/v3/projects/${encodeURIComponent(projectId)}`);
      if (!projectRes.ok) continue;
      const projectData: any = await projectRes.json();

      const checks: Array<{ name: string; score: number }> = projectData.scorecard?.checks || [];
      const lowChecks = checks.filter((c) => typeof c.score === 'number' && c.score >= 0 && c.score <= 3);
      if (lowChecks.length > 0) {
        const detail = lowChecks.map((c) => `${c.name}: ${c.score}/10`).join(', ');
        findings.push(`${dep.name}@${dep.version} — low OpenSSF Scorecard checks (${detail})`);
      }
    } catch (err) {
      console.error(`Scorecard lookup failed for ${dep.name} (failing open):`, err);
    }
  }

  return findings;
}

// Posts a PR comment and surfaces failure instead of swallowing it — a plain
// fetch() doesn't throw on 403/404, so an unchecked call here previously
// looked identical (in logs and to the Alarm's own "Ok" status) whether the
// comment posted or GitHub rejected it (e.g. "Resource not accessible by
// integration" when the App has pull_requests:write but not the issues:write
// that POST /issues/{n}/comments — which is what pr.comments_url points
// to — actually requires).
async function postPrComment(commentsUrl: string, token: string, body: string): Promise<void> {
  const res = await fetch(commentsUrl, {
    method: 'POST',
    headers: {
      'Authorization': `token ${token}`,
      'User-Agent': 'Cloudflare-Code-Reviewer',
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ body })
  });
  if (!res.ok) {
    console.error(`Failed to post PR comment: ${res.status} ${res.statusText} — ${await res.text()}`);
  }
}

// ── Inline Review Suggestions (GitHub Pull Request Reviews API) ────────────────
// A ```suggestion block only becomes a one-click "Commit suggestion" button
// when it lives in a review comment anchored to a line of the diff — inside
// an issue comment it's just a code block. GitHub rejects the entire review
// (422) if any comment points at a line outside the diff's hunks, so every
// finding is validated against the set of commentable new-file lines first.

interface InlineFinding {
  path: string;
  startLine?: number;
  line: number;
  title: string;
  body: string;
  suggestion?: string;
}

// path → (new-file line number → line text) for every line in the diff
// (added or context). These are exactly the RIGHT-side lines GitHub accepts
// comments on.
function commentableLines(files: parseDiff.File[]): Map<string, Map<number, string>> {
  const map = new Map<string, Map<number, string>>();
  for (const file of files) {
    if (!file.to || file.to === '/dev/null') continue;
    const lines = new Map<number, string>();
    for (const chunk of file.chunks) {
      for (const change of chunk.changes) {
        if (change.type === 'add') lines.set(change.ln, change.content.slice(1));
        else if (change.type === 'normal') lines.set(change.ln2, change.content.slice(1));
      }
    }
    map.set(file.to, lines);
  }
  return map;
}

const leadingWhitespace = (s: string) => s.match(/^\s*/)![0];

// Models routinely (a) strip indentation from suggestions and (b) rewrite the
// lines *after* the cited one without widening the range — committing that
// suggestion would duplicate those lines. Both are fixable deterministically
// against the real file lines, so the one-click button produces valid code.
function fitSuggestion(f: InlineFinding, lines: Map<number, string>): InlineFinding {
  if (f.suggestion === undefined) return f;
  let suggestion = f.suggestion.split('\n');
  let line = f.line;

  // (b) Widen the range backward while the suggestion's leading lines repeat
  // the lines just above it (the model rewrote 9–11 but cited 10), then
  // forward while its trailing lines repeat the lines that follow it — they
  // were meant to be replaced, not duplicated.
  let startLine = f.startLine ?? f.line;
  for (let m = suggestion.length - 1; m > 0; m--) {
    let matches = true;
    for (let k = 0; k < m && matches; k++) {
      const orig = lines.get(startLine - m + k);
      matches = orig !== undefined && suggestion[k].trim() === orig.trim();
    }
    if (matches) {
      startLine -= m;
      break;
    }
  }
  const prepended = (f.startLine ?? f.line) - startLine;
  for (let k = suggestion.length - 1 - prepended; k > 0; k--) {
    let matches = true;
    for (let j = 1; j <= k && matches; j++) {
      const orig = lines.get(line + j);
      matches = orig !== undefined && suggestion[suggestion.length - 1 - k + j].trim() === orig.trim();
    }
    if (matches) {
      line += k;
      break;
    }
  }

  // (a) Re-indent so the first line matches the original's indentation;
  // lines the suggestion leaves unchanged keep their original text verbatim.
  const want = leadingWhitespace(lines.get(startLine) ?? '');
  const have = leadingWhitespace(suggestion[0]);
  const pad = want.length > have.length && suggestion[0].trim() !== '' ? want.slice(have.length) : '';
  suggestion = suggestion.map((s, i) => {
    const orig = lines.get(startLine + i);
    if (orig !== undefined && startLine + i <= line && s.trim() === orig.trim()) return orig;
    return s.trim() === '' ? s : pad + s;
  });

  return { ...f, startLine: line > startLine ? startLine : undefined, line, suggestion: suggestion.join('\n') };
}

// Renders the diff with explicit new-file line numbers so the model can cite
// a line GitHub will accept, instead of guessing from raw hunk headers.
function renderNumberedDiff(files: parseDiff.File[], maxChars = 12000): string {
  const out: string[] = [];
  for (const file of files) {
    if (!file.to || file.to === '/dev/null') continue;
    out.push(`=== ${file.to} ===`);
    for (const chunk of file.chunks) {
      for (const change of chunk.changes) {
        const text = change.content.slice(1);
        if (change.type === 'add') out.push(`${String(change.ln).padStart(4)} + ${text}`);
        else if (change.type === 'normal') out.push(`${String(change.ln2).padStart(4)}   ${text}`);
        else out.push(`     - ${text}`);
      }
    }
  }
  return out.join('\n').slice(0, maxChars);
}

// Workers AI hands back already-parsed JSON when the model's whole output is
// valid JSON, so `response` may be an array/object rather than a string.
function parseInlineFindings(response: unknown): InlineFinding[] {
  let raw: any = response;
  if (typeof response === 'string') {
    // R1-style models may prefix their answer with a <think> block.
    const cleaned = response.replace(/<think>[\s\S]*?<\/think>/g, '');
    const match = cleaned.match(/\[[\s\S]*\]/);
    if (!match) return [];
    try {
      raw = JSON.parse(match[0]);
    } catch {
      return [];
    }
  }
  if (raw && !Array.isArray(raw) && Array.isArray(raw.findings)) raw = raw.findings;
  if (!Array.isArray(raw)) return [];
  return raw
    .filter((f) => f && typeof f.path === 'string' && Number.isInteger(f.line) && typeof f.title === 'string')
    .map((f) => ({
      path: f.path,
      startLine: Number.isInteger(f.start_line) && f.start_line < f.line ? f.start_line : undefined,
      line: f.line,
      title: f.title,
      body: typeof f.body === 'string' ? f.body : '',
      suggestion: typeof f.suggestion === 'string' ? f.suggestion.replace(/\n$/, '') : undefined,
    }));
}

// Drops findings GitHub would reject: unknown path, or any line of the
// (start_line..line) range falling outside the diff.
function anchorFindings(findings: InlineFinding[], files: parseDiff.File[]): InlineFinding[] {
  const lines = commentableLines(files);
  return findings
    .filter((f) => {
      const valid = lines.get(f.path);
      if (!valid) return false;
      for (let ln = f.startLine ?? f.line; ln <= f.line; ln++) {
        if (!valid.has(ln)) return false;
      }
      return true;
    })
    .map((f) => fitSuggestion(f, lines.get(f.path)!))
    // A suggestion identical to the lines it replaces is a false alarm —
    // the model "fixed" code that was already correct.
    .filter((f) => {
      if (f.suggestion === undefined) return true;
      const valid = lines.get(f.path)!;
      const original: string[] = [];
      for (let ln = f.startLine ?? f.line; ln <= f.line; ln++) original.push(valid.get(ln)!.trim());
      return f.suggestion.split('\n').map((s) => s.trim()).join('\n') !== original.join('\n');
    });
}

function renderInlineComment(f: InlineFinding): Record<string, unknown> {
  const suggestion = f.suggestion !== undefined ? `\n\n\`\`\`suggestion\n${f.suggestion}\n\`\`\`` : '';
  const comment: Record<string, unknown> = {
    path: f.path,
    line: f.line,
    side: 'RIGHT',
    body: `**${f.title}**\n\n${f.body}${suggestion}`,
  };
  if (f.startLine !== undefined) {
    comment.start_line = f.startLine;
    comment.start_side = 'RIGHT';
  }
  return comment;
}

// Posts the arbiter summary as the review body with each anchored finding as
// an inline comment. Returns false on failure so the caller can fall back to
// a plain issue comment rather than dropping the review.
async function postPrReview(
  repoFullName: string,
  prNumber: number,
  commitSha: string,
  token: string,
  body: string,
  findings: InlineFinding[]
): Promise<boolean> {
  const res = await fetch(`https://api.github.com/repos/${repoFullName}/pulls/${prNumber}/reviews`, {
    method: 'POST',
    headers: {
      'Authorization': `token ${token}`,
      'User-Agent': 'Cloudflare-Code-Reviewer',
      'Accept': 'application/vnd.github+json',
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ commit_id: commitSha, event: 'COMMENT', body, comments: findings.map(renderInlineComment) })
  });
  if (!res.ok) {
    console.error(`Failed to post PR review: ${res.status} ${res.statusText} — ${await res.text()}`);
    return false;
  }
  return true;
}

// ── Durable Object: State, Debounce & Multi-Model Committee ────────────────────
export class PrReviewCoordinator extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    // Schema setup only — block concurrency so no request is served against
    // a table that hasn't been created yet.
    ctx.blockConcurrencyWhile(async () => {
      this.ctx.storage.sql.exec(`
        CREATE TABLE IF NOT EXISTS reviews (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          commit_sha TEXT,
          summary TEXT,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
      `);
    });
  }

  async fetch(request: Request): Promise<Response> {
    const payload: any = await request.json();
    const pr = payload.pull_request;

    // 1. Debounce rapid pushes: Reset alarm for 15 seconds
    await this.ctx.storage.setAlarm(Date.now() + 15000);
    await this.ctx.storage.put('pending_pr', pr);
    await this.ctx.storage.put('repo_full_name', payload.repository.full_name);
    // Present only on deliveries from the GitHub App installation — Advanced
    // is App-only, so no installation.id means no way to post at all.
    if (payload.installation?.id) {
      await this.ctx.storage.put('installation_id', payload.installation.id);
    }

    return new Response(JSON.stringify({ status: 'queued', pr: pr.number, debounce_seconds: 15 }), {
      headers: { 'Content-Type': 'application/json' }
    });
  }

  // Fired after 15 seconds of silence (no new commits pushed)
  async alarm() {
    const pr: any = await this.ctx.storage.get('pending_pr');
    const repoFullName: string | undefined = await this.ctx.storage.get('repo_full_name');
    const installationId: number | undefined = await this.ctx.storage.get('installation_id');
    if (!pr || !repoFullName) return;

    // App-only: the Advanced Track posts exclusively as the
    // clawbuilders-code-reviewer[bot] GitHub App identity, no PAT fallback.
    // null when the App isn't configured or this delivery didn't come from
    // an installation — both posting sites below already handle a falsy
    // token by skipping silently, same as before. Resolved once and reused
    // for both the early Pillar-1 block and the final post.
    let githubToken: string | undefined;
    try {
      githubToken = (await resolveGitHubToken(this.env, installationId)) ?? undefined;
    } catch (tokenErr: any) {
      console.error('resolveGitHubToken threw:', tokenErr?.message ?? tokenErr);
    }

    // Every AI Gateway option below is what actually turns on the 24h cache,
    // analytics, and fallback routing — without this 3rd argument,
    // env.AI.run() calls Workers AI directly and none of that applies.
    const gatewayOpts = this.env.AI_GATEWAY_NAME
      ? { gateway: { id: this.env.AI_GATEWAY_NAME, cacheTtl: 86400 } }
      : undefined;

    try {
      // 1. Fetch the diff via the REST API (not the github.com "/pull/N.diff"
      // web route pr.diff_url points to). A valid App installation token
      // still gets a 404 from that web route on a private repo — it isn't
      // reliably token-authenticated the way the REST API is — so this uses
      // the documented way to get a diff: GET the PR resource with the
      // v3.diff media type.
      const diffHeaders: Record<string, string> = {
        'User-Agent': 'Cloudflare-Code-Reviewer',
        'Accept': 'application/vnd.github.v3.diff'
      };
      if (githubToken) diffHeaders['Authorization'] = `token ${githubToken}`;
      const diffApiUrl = `https://api.github.com/repos/${repoFullName}/pulls/${pr.number}`;
      const diffResponse = await fetch(diffApiUrl, { headers: diffHeaders });
      if (!diffResponse.ok) {
        console.error(`Failed to fetch PR diff: ${diffResponse.status} ${diffResponse.statusText} from ${diffApiUrl}`);
        await this.ctx.storage.delete('pending_pr');
        return;
      }
      const diffText = await diffResponse.text();

      // ── PILLAR 1: Gitleaks-pattern Zero-Tolerance Secret Gate ───────────────
      const leakedSecrets = scanForSecrets(diffText);
      if (leakedSecrets.length > 0) {
        if (githubToken) {
          await postPrComment(
            pr.comments_url,
            githubToken,
            `### 🚨 [CRITICAL SECURITY BLOCK — Gitleaks-pattern Scan]\n\nHardcoded credentials detected in PR diff: **${leakedSecrets.join(', ')}**.\n\nPlease revoke this token immediately and remove it from git history before merging.`
          );
        } else {
          console.error('Secrets detected but no githubToken resolved — cannot post block comment.');
        }
        await this.ctx.storage.delete('pending_pr');
        return;
      }

      const parsedFiles = parseDiff(diffText);
      const dependencyUpdates = extractPackageJsonDependencyUpdates(parsedFiles);

      // ── PILLAR 2: OSV.dev Vulnerability Lookup (real API) ───────────────────
      const vulnerabilityFindings = await checkOsvVulnerabilities(dependencyUpdates);

      // ── PILLAR 3: Hard-Rails File Filter (Alibaba OCR noise reduction) ─────
      const reviewableFiles = parsedFiles.filter(file => {
        const path = file.to || '';
        return !path.endsWith('.lock') &&
               !path.endsWith('.yaml') &&
               !path.endsWith('.yml') &&
               !path.endsWith('.md') &&
               !path.includes('dist/') &&
               !path.includes('vendor/') &&
               !path.includes('build/');
      });

      // ── PILLAR 4: OPA-inspired Blast Radius & Scope Gate ────────────────────
      const policyAlerts = evaluateOpaPolicy(parsedFiles);

      // ── PILLAR 7: OpenSSF Scorecard Supply-Chain Check (real API) ───────────
      const scorecardFindings = await checkSupplyChainScorecard(dependencyUpdates);

      if (reviewableFiles.length === 0 && dependencyUpdates.length === 0) {
        await this.ctx.storage.delete('pending_pr');
        return;
      }

      const diffHunk = JSON.stringify(reviewableFiles.slice(0, 5));
      const numberedDiff = renderNumberedDiff(reviewableFiles.slice(0, 5));

      // ── CLEF TRIAGE GATE: which specialist(s) does this diff actually need? ──
      // Falls back through a free-tier model, then fails open, if Clef itself
      // is unavailable — see the `triage()` doc
      // comment above for the full cascade.
      const escalationFloor = parseFloat(this.env.JEV_ESCALATION_FLOOR ?? '0.5') || 0.5;
      const triage = await runTriage(
        this.env.AI,
        reviewableFiles,
        diffHunk,
        policyAlerts,
        vulnerabilityFindings,
        escalationFloor,
        gatewayOpts
      );
      const triageSourceNote =
        triage.source === 'fallback-model'
          ? ' _(Clef was unavailable this run — triage fell back to a free-tier model instead.)_'
          : triage.source === 'fail-open'
            ? ' _(Both Clef and the free-tier fallback were unavailable — running the full committee to be safe rather than skipping.)_'
            : '';

      if (!triage.needsSecurity && !triage.needsQuality) {
        const skipSummary = `### 🛡️ AI Review Committee — Clef Triage\n\n[clef-flash](https://developers.cloudflare.com/workers-ai/models/clef-flash/) classified this as a **${triage.category}** change with no security or code-quality signal worth a full multi-model review (security confidence ${triage.securityNoul.toFixed(2)}, quality confidence ${triage.qualityNoul.toFixed(2)}). Skipping DeepSeek-R1 + Qwen 2.5 Coder for this PR.${triageSourceNote}\n\n_Deterministic checks (secret scan, OSV.dev, policy gate) already ran above and would have forced a full review automatically if any of them had found something._`;
        this.ctx.storage.sql.exec(
          'INSERT INTO reviews (commit_sha, summary) VALUES (?, ?)',
          pr.head.sha,
          skipSummary
        );
        if (githubToken) {
          await postPrComment(pr.comments_url, githubToken, skipSummary);
        }
        await this.ctx.storage.delete('pending_pr');
        return;
      }

      // ── PILLAR 5: Mantis-style Reachability Context (real GitHub content) ──
      // Only fetched when the security specialist is actually going to run —
      // it exists solely to feed that specialist's reachability reasoning.
      const fullFileContext = triage.needsSecurity
        ? await fetchFullFileContext(
            repoFullName,
            pr.head.sha,
            reviewableFiles.slice(0, 5).map((f) => f.to || '').filter(Boolean),
            githubToken
          )
        : '';

      // ── MULTI-MODEL PARALLEL EVALUATION (Promise.all) ──────────────────────
      // Each specialist only runs if the Clef triage gate above said it's
      // needed — a docs-only or dependency-bump PR skips both and never
      // reaches this point at all (see the early return above).
      const [securityReport, codeReport] = await Promise.all([
        // Security Specialist: DeepSeek R1 does Mantis-style reachability reasoning
        triage.needsSecurity
          ? this.env.AI.run('@cf/deepseek-ai/deepseek-r1-distill-qwen-32b', {
              messages: [
                {
                  role: 'system',
                  content: `You are a security auditor doing Mantis-style verification: don't just pattern-match, check whether a flagged issue is actually REACHABLE given the full file context provided.
Look for:
- Null Pointer Exceptions (NPE) & undefined dereferencing
- SQL / Command injection & sanitization bypasses
- Concurrency race conditions & unclosed resource leaks
If a candidate issue is not reachable from the code shown, say so explicitly and do not report it.
If nothing is reachable and exploitable, respond with NONE.`
                },
                { role: 'user', content: `Diff hunk:\n${diffHunk}\n\n${fullFileContext ? `Full file context for reachability analysis:\n${fullFileContext}` : '(No full-file context available — reason from the diff hunk alone.)'}` }
              ]
            }, gatewayOpts)
          : Promise.resolve(null),

        // Code Quality Specialist: Alibaba Qwen 2.5 Coder (Clean Syntax & Fix Generation)
        triage.needsQuality
          ? this.env.AI.run('@cf/qwen/qwen2.5-coder-32b-instruct', {
              messages: [
                {
                  role: 'system',
                  content: `You are a staff software engineer performing code review following Alibaba OCR rules.
The diff is shown with new-file line numbers in the left column ("+" = added line, blank = unchanged context, "-" = removed line with no number).
Report only substantive defects (bugs, security issues, missing error handling), not style nitpicks.
Respond with ONLY a JSON array, no prose, no markdown fences. Each element:
{"path": "<file path exactly as shown after ===>", "start_line": <optional first line number of a multi-line range>, "line": <line number>, "title": "<short defect name>", "body": "<one or two sentences explaining the defect>", "suggestion": "<exact replacement code for lines start_line..line (or just line), preserving indentation>"}
Only cite numbered lines. Omit "suggestion" if the fix can't be expressed as a replacement of those exact lines. Return [] if there are no substantive issues.`
                },
                { role: 'user', content: numberedDiff }
              ]
            }, gatewayOpts)
          : Promise.resolve(null)
      ]);

      // Qwen's findings become inline review comments; only those anchored to
      // a real diff line survive, and the arbiter sees them as a plain list.
      const inlineFindings = codeReport
        ? anchorFindings(parseInlineFindings(codeReport.response), reviewableFiles)
        : [];
      const codeReportSummary = !codeReport
        ? 'Skipped — Clef triage found no substantive quality signal in this diff'
        : inlineFindings.length === 0
          ? 'No substantive issues found'
          : inlineFindings.map((f) => `${f.path}:${f.line} — ${f.title}: ${f.body}`).join('\n');

      // ── PILLAR 6: OWASP-ASRH-style Regression Check + Lead Arbiter Synthesis ─
      const finalSynthesis = await this.env.AI.run('@cf/meta/llama-3.3-70b-instruct-fp8-fast', {
        messages: [
          {
            role: 'system',
            content: `You are the Lead Code Review Arbiter, applying an OWASP-Agent-Security-Regression-Harness-style checklist. You received reports from the 7-pillar pipeline:
- OPA-style Policy & Blast Radius: ${policyAlerts.length > 0 ? policyAlerts.join('; ') : 'Safe scope'}
- OSV.dev Vulnerability Lookup: ${vulnerabilityFindings.length > 0 ? vulnerabilityFindings.join('; ') : 'No known vulnerabilities in changed dependencies'}
- OpenSSF Scorecard Supply-Chain Check: ${scorecardFindings.length > 0 ? scorecardFindings.join('; ') : 'No low-scoring dependencies flagged'}
- Security Specialist (Mantis-style reachability): ${securityReport ? securityReport.response : 'Skipped — Clef triage found no plausible security signal in this diff'}
- Code Quality Specialist (Qwen 2.5 Coder): ${codeReportSummary}
${inlineFindings.length > 0 ? `\nThe Code Quality findings above are already posted as inline comments with one-click suggestions on the exact lines — reference them briefly, do not repeat their code fixes.\n` : ''}

Verification Checklist:
1. Ensure proposed fixes introduce ZERO secondary regressions or permission leaks.
2. Deduplicate overlapping comments and eliminate false alarms.
3. Format output with badges: [SECURITY], [POLICY], [DEPENDENCY], [SUPPLY-CHAIN], [CODE QUALITY].

Apply this checklist silently. Output ONLY the final review a developer reads: a one-line verdict, then one bullet per confirmed finding prefixed with its badge. Do not restate these instructions or the checklist.`
          },
          { role: 'user', content: `Original diff:\n${diffHunk}` }
        ]
      }, gatewayOpts);

      // Save review into Durable Object SQLite storage
      this.ctx.storage.sql.exec(
        'INSERT INTO reviews (commit_sha, summary) VALUES (?, ?)',
        pr.head.sha,
        finalSynthesis.response
      );

      // Post final review back to GitHub PR
      if (githubToken) {
        const reviewBody = `### 🛡️ AI Review Committee (7-Pillar Security Suite)\n*Gitleaks-pattern • OSV.dev (live) • Hard-Rails Filter • Clef Triage Gate • OPA-inspired Policy • Mantis-style Reachability • OWASP-ASRH-style Regression • OpenSSF Scorecard (live)*\n\n${!triage.needsSecurity ? '_Security specialist skipped by Clef triage for this PR._\n\n' : ''}${!triage.needsQuality ? '_Code quality specialist skipped by Clef triage for this PR._\n\n' : ''}${triageSourceNote ? triageSourceNote.trim() + '\n\n' : ''}${finalSynthesis.response}`;
        const posted = await postPrReview(repoFullName, pr.number, pr.head.sha, githubToken, reviewBody, inlineFindings);
        if (!posted) {
          // Inline anchoring failed (e.g. a stale head SHA) — still deliver the
          // review, with the suggestions inlined as plain text.
          const fallbackFindings = inlineFindings
            .map((f) => `- \`${f.path}:${f.line}\` **${f.title}** — ${f.body}${f.suggestion !== undefined ? `\n  \`\`\`suggestion\n${f.suggestion}\n  \`\`\`` : ''}`)
            .join('\n');
          await postPrComment(pr.comments_url, githubToken, fallbackFindings ? `${reviewBody}\n\n${fallbackFindings}` : reviewBody);
        }
      } else {
        console.error(
          `No githubToken resolved for ${repoFullName}#${pr.number} — review computed but not posted. ` +
          `Check GITHUB_APP_ID/GITHUB_APP_PRIVATE_KEY and that the webhook payload carried installation.id.`
        );
      }
    } catch (err: any) {
      console.error('Error running review:', err);
    } finally {
      await this.ctx.storage.delete('pending_pr');
      await this.ctx.storage.delete('repo_full_name');
      await this.ctx.storage.delete('installation_id');
    }
  }
}
