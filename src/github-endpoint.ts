/**
 * github-endpoint.ts
 * Provides POST /api/audit/github  { repoUrl: string }
 * Scans a GitHub repo for .fc / .tact / .func contracts and audits them via SSE.
 */
import type { Application, Request, Response } from "express";
import path from "path";
import { auditContract, AuditReport } from "./auditor";

// Re-export from server so the route can reference BatchReport / buildComparison.
// We import them lazily at registration time to avoid circular imports.
export interface GHBatchReport {
  auditedAt: string;
  totalContracts: number;
  reports: AuditReport[];
  comparison: {
    riskRanking: { contractName: string; score: number; overallRisk: string }[];
    totalFindings: number;
    criticalCount: number;
    highCount: number;
    mostVulnerable: string;
    safest: string;
    commonCategories: { category: string; count: number }[];
  };
}

const GITHUB_CONTRACT_EXTS = [".fc", ".func", ".tact"];
const GITHUB_API_BASE = "https://api.github.com";
const GITHUB_TOKEN = process.env.GITHUB_TOKEN;

function githubHeaders(): Record<string, string> {
  const h: Record<string, string> = {
    "User-Agent": "TonAudit-AI/1.0",
    Accept: "application/vnd.github.v3+json",
  };
  if (GITHUB_TOKEN) h["Authorization"] = `token ${GITHUB_TOKEN}`;
  return h;
}

async function ghFetchJSON(url: string): Promise<unknown> {
  const res = await fetch(url, { headers: githubHeaders() });
  if (!res.ok) throw new Error(`GitHub API ${res.status}: ${await res.text()}`);
  return res.json();
}

interface GHTreeItem { path: string; type: string; }

async function findContractFiles(
  owner: string,
  repo: string,
  ref = "HEAD",
): Promise<{ filePath: string; downloadUrl: string }[]> {
  const tree = (await ghFetchJSON(
    `${GITHUB_API_BASE}/repos/${owner}/${repo}/git/trees/${ref}?recursive=1`,
  )) as { tree: GHTreeItem[] };

  return tree.tree
    .filter(
      (item) =>
        item.type === "blob" &&
        GITHUB_CONTRACT_EXTS.includes(path.extname(item.path).toLowerCase()),
    )
    .slice(0, 10)
    .map((item) => ({
      filePath: item.path,
      downloadUrl: `https://raw.githubusercontent.com/${owner}/${repo}/${ref}/${item.path}`,
    }));
}

function buildGHComparison(reports: AuditReport[]): GHBatchReport["comparison"] {
  const riskRanking = reports
    .map((r) => ({ contractName: r.contractName, score: r.score, overallRisk: r.overallRisk }))
    .sort((a, b) => a.score - b.score);
  const allFindings = reports.flatMap((r) => r.findings);
  const catCounts: Record<string, number> = {};
  for (const f of allFindings) catCounts[f.category] = (catCounts[f.category] ?? 0) + 1;
  const commonCategories = Object.entries(catCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([category, count]) => ({ category, count }));
  return {
    riskRanking,
    totalFindings: allFindings.length,
    criticalCount: allFindings.filter((f) => f.severity === "critical").length,
    highCount: allFindings.filter((f) => f.severity === "high").length,
    mostVulnerable: riskRanking[0]?.contractName ?? "N/A",
    safest: riskRanking[riskRanking.length - 1]?.contractName ?? "N/A",
    commonCategories,
  };
}

export function registerGithubAuditRoute(app: Application): void {
  app.post("/api/audit/github", async (req: Request, res: Response) => {
    const { repoUrl } = req.body as { repoUrl?: string };
    if (!repoUrl) return res.status(400).json({ error: "repoUrl is required" });

    const match = repoUrl.match(
      /github\.com\/([a-zA-Z0-9_.-]+)\/([a-zA-Z0-9_.-]+)/,
    );
    if (!match) return res.status(400).json({ error: "Invalid GitHub URL" });
    const [, owner, repo] = match;

    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache");
    res.setHeader("Connection", "keep-alive");
    res.flushHeaders();

    const send = (event: string, data: unknown) =>
      res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);

    const BATCH_TIMEOUT_MS = 5 * 60 * 1000;
    const CONTRACT_TIMEOUT_MS = 90 * 1000;
    const rejectAfter = (ms: number, label: string): Promise<never> =>
      new Promise((_, rej) =>
        setTimeout(() => rej(new Error(`Timeout: ${label} exceeded ${ms / 1000}s`)), ms),
      );

    try {
      send("status", { message: `🔍 Scanning ${owner}/${repo} for smart contracts…` });

      const files = await findContractFiles(owner, repo);
      if (files.length === 0) {
        send("error", { message: `No .fc/.tact/.func files found in ${owner}/${repo}` });
        return res.end();
      }
      send("status", {
        message: `📦 Found ${files.length} contract(s) — starting audit…`,
        total: files.length,
      });

      const reports: AuditReport[] = [];
      const deadline = Date.now() + BATCH_TIMEOUT_MS;

      for (let i = 0; i < files.length; i++) {
        if (Date.now() >= deadline) {
          send("partial_error", {
            index: i, filename: files[i].filePath,
            error: "Batch timeout (5 min): skipped remaining",
          });
          break;
        }
        const { filePath, downloadUrl } = files[i];
        const filename = path.basename(filePath);
        send("progress", {
          message: `🔍 Auditing ${filename} (${i + 1}/${files.length})…`,
          current: i + 1, total: files.length, filename, repoPath: filePath,
        });
        try {
          const codeRes = await fetch(downloadUrl, { headers: githubHeaders() });
          if (!codeRes.ok) throw new Error(`Download failed: ${codeRes.status}`);
          const code = await codeRes.text();
          const report = await Promise.race([
            auditContract(code, filename, () => {}),
            rejectAfter(CONTRACT_TIMEOUT_MS, filename),
          ]);
          reports.push(report);
          send("partial", { index: i, filename, score: report.score, risk: report.overallRisk });
        } catch (err) {
          send("partial_error", {
            index: i, filename,
            error: err instanceof Error ? err.message : "Audit failed",
          });
        }
      }

      if (reports.length === 0) {
        send("error", { message: "All audits failed" });
        return res.end();
      }

      const batchReport: GHBatchReport = {
        auditedAt: new Date().toISOString(),
        totalContracts: files.length,
        reports,
        comparison: buildGHComparison(reports),
      };
      send("batch_report", batchReport);
      res.write("event: done\ndata: {}\n\n");
      res.end();
    } catch (err) {
      send("error", { message: err instanceof Error ? err.message : "GitHub scan failed" });
      res.end();
    }
  });
}
