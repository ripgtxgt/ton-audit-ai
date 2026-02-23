import OpenAI from "openai";

// Use claude-max local proxy (OpenAI-compatible)
const client = new OpenAI({
  baseURL: process.env.CLAUDE_API_BASE || "http://localhost:8317/v1",
  apiKey: process.env.CLAUDE_API_KEY || "claude-max",
});

const MODEL = process.env.AUDIT_MODEL || "claude-sonnet-4-5-20250929";

export type ContractLanguage = "func" | "tact" | "unknown";

export interface Finding {
  id: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  category: string;
  title: string;
  description: string;
  location?: string;
  recommendation: string;
  codeSnippet?: string;
}

export interface AuditReport {
  contractName: string;
  language: ContractLanguage;
  linesOfCode: number;
  auditedAt: string;
  overallRisk: "critical" | "high" | "medium" | "low" | "clean";
  summary: string;
  findings: Finding[];
  gasAnalysis: string;
  architectureNotes: string;
  score: number; // 0-100, higher = more secure
}

export function detectLanguage(code: string, filename?: string): ContractLanguage {
  if (filename?.endsWith(".tact")) return "tact";
  if (filename?.endsWith(".fc") || filename?.endsWith(".func")) return "func";
  if (code.includes("contract ") && code.includes("fun ")) return "tact";
  if (code.includes("() impure") || code.includes("recv_internal") || code.includes("#include")) return "func";
  return "unknown";
}

const AUDIT_SYSTEM_PROMPT = `You are TonAudit AI, an expert TON blockchain smart contract security auditor with deep knowledge of:
- FunC language (TON's primary smart contract language)
- Tact language (TON's newer high-level language)
- TON Virtual Machine (TVM) internals and opcodes
- Common TON-specific vulnerabilities and attack vectors
- TON ecosystem standards (TEP-64, TEP-74 Jettons, TEP-62 NFT)
- Gas optimization patterns for TON

Your analysis must be thorough, precise, and actionable. Always respond with valid JSON matching the specified schema exactly.`;

function buildAuditPrompt(code: string, language: ContractLanguage, filename?: string): string {
  const langInfo = language === "func"
    ? "FunC (TON's low-level smart contract language)"
    : language === "tact"
    ? "Tact (TON's high-level smart contract language)"
    : "TON smart contract (language auto-detected)";

  return `Perform a comprehensive security audit of this ${langInfo} contract${filename ? ` (${filename})` : ""}.

\`\`\`${language === "func" ? "func" : language === "tact" ? "tact" : ""}
${code}
\`\`\`

Analyze for ALL of the following vulnerability categories:

**TON-Specific Issues:**
- Reentrancy via message chains (TON async model)
- Improper bounce message handling (missing bounce handlers)
- Unauthorized message senders (missing sender validation)
- Wrong workchain assumptions (masterchain vs basechain)
- Storage fee exhaustion (contract death from insufficient balance)
- Jetton standard deviations (TEP-74 compliance)
- NFT standard deviations (TEP-62 compliance)
- Improper use of raw_reserve vs send_raw_message modes

**General Smart Contract Issues:**
- Integer overflow/underflow
- Access control vulnerabilities
- Replay attack vectors
- Front-running vulnerabilities
- Unvalidated external inputs
- Improper state management
- Missing error handling

**Gas & Economic Issues:**
- Gas griefing attacks
- Unpredictable gas consumption
- Inefficient cell/slice operations
- Missing gas fees forwarding

Respond ONLY with valid, minified JSON (no extra whitespace or newlines outside string values) in this exact schema:
{
  "overallRisk": "critical|high|medium|low|clean",
  "summary": "2-3 sentence executive summary",
  "score": <integer 0-100, where 100 is perfectly secure>,
  "findings": [
    {
      "severity": "critical|high|medium|low|info",
      "category": "category name",
      "title": "short title",
      "description": "detailed description of the vulnerability (plain text, no code blocks)",
      "location": "function name or line reference",
      "recommendation": "specific actionable fix (plain text only, no code blocks or backticks)",
      "codeSnippet": "single short line showing the vulnerable code (optional, max 120 chars, no newlines)"
    }
  ],
  "gasAnalysis": "plain text gas analysis",
  "architectureNotes": "plain text architecture notes"
}

IMPORTANT:
- All string values must be single-line (no newlines, no backtick code blocks inside JSON strings)
- Do NOT include code examples with backticks inside JSON string values
- The entire response must be parseable by JSON.parse() without error
- Order findings by severity (critical first)
- Omit codeSnippet if it would be longer than 120 characters`;
}

export async function auditContract(
  code: string,
  filename?: string,
  onChunk?: (chunk: string) => void
): Promise<AuditReport> {
  const language = detectLanguage(code, filename);
  const lines = code.split("\n").filter((l) => l.trim().length > 0).length;

  let fullResponse = "";

  const stream = await client.chat.completions.create({
    model: MODEL,
    max_tokens: 4096,
    stream: true,
    messages: [
      { role: "system", content: AUDIT_SYSTEM_PROMPT },
      { role: "user", content: buildAuditPrompt(code, language, filename) },
    ],
  });

  for await (const chunk of stream) {
    const delta = chunk.choices[0]?.delta?.content || "";
    fullResponse += delta;
    if (delta) onChunk?.(delta);
  }

  // Parse JSON — Claude sometimes wraps in markdown code fences
  const jsonMatch = fullResponse.match(/\{[\s\S]*\}/);
  if (!jsonMatch) {
    throw new Error("Failed to parse audit response as JSON. Raw: " + fullResponse.slice(0, 200));
  }

  let jsonStr = jsonMatch[0];

  // Sanitize: replace literal newlines inside JSON string values with \n escape
  // This handles cases where Claude puts multi-line content inside strings
  jsonStr = jsonStr.replace(
    /"(?:[^"\\]|\\.)*"/g,
    (match) => match.replace(/\n/g, "\\n").replace(/\r/g, "\\r").replace(/\t/g, "\\t")
  );

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let parsed: any;
  try {
    parsed = JSON.parse(jsonStr);
  } catch (e) {
    // Last resort: strip all control characters and retry
    const cleaned = jsonStr.replace(/[\x00-\x1F\x7F]/g, (c) => {
      if (c === "\n") return "\\n";
      if (c === "\r") return "\\r";
      if (c === "\t") return "\\t";
      return "";
    });
    try {
      parsed = JSON.parse(cleaned);
    } catch {
      throw new Error(`JSON parse failed. First 500 chars: ${fullResponse.slice(0, 500)}`);
    }
  }

  const findings: Finding[] = (parsed.findings || []).map(
    (f: Omit<Finding, "id">, i: number) => ({
      ...f,
      id: `TON-${String(i + 1).padStart(3, "0")}`,
    })
  );

  return {
    contractName: filename?.replace(/\.[^.]+$/, "") || "Unknown Contract",
    language,
    linesOfCode: lines,
    auditedAt: new Date().toISOString(),
    overallRisk: parsed.overallRisk || "medium",
    summary: parsed.summary || "",
    findings,
    gasAnalysis: parsed.gasAnalysis || "",
    architectureNotes: parsed.architectureNotes || "",
    score: Math.max(0, Math.min(100, parsed.score || 50)),
  };
}
