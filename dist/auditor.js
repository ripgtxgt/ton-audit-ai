"use strict";
/**
 * auditor.ts — AI analysis engine
 *
 * API routing:
 *   - If ANTHROPIC_API_KEY is set → use Anthropic API directly (production)
 *   - Else if CLAUDE_API_BASE is set → use OpenAI-compat local proxy (dev)
 *   - Else → fall back to localhost:8317 (openclaw default)
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.detectLanguage = detectLanguage;
exports.auditContract = auditContract;
const sdk_1 = __importDefault(require("@anthropic-ai/sdk"));
const openai_1 = __importDefault(require("openai"));
// ─── Client factory ────────────────────────────────────────────────────────────
const ANTHROPIC_KEY = process.env.ANTHROPIC_API_KEY;
const CLAUDE_BASE = process.env.CLAUDE_API_BASE || "http://localhost:8317/v1";
const CLAUDE_KEY = process.env.CLAUDE_API_KEY || "claude-max";
const MODEL = process.env.AUDIT_MODEL || "claude-opus-4-5-20251101";
// Use official Anthropic SDK when ANTHROPIC_API_KEY is present (production),
// otherwise fall back to OpenAI-compat proxy (local dev via openclaw).
const useAnthropicDirect = Boolean(ANTHROPIC_KEY);
const anthropicClient = useAnthropicDirect
    ? new sdk_1.default({ apiKey: ANTHROPIC_KEY })
    : null;
const openaiClient = !useAnthropicDirect
    ? new openai_1.default({ baseURL: CLAUDE_BASE, apiKey: CLAUDE_KEY })
    : null;
console.log(useAnthropicDirect
    ? `🤖 Using Anthropic API directly (${MODEL})`
    : `🤖 Using OpenAI-compat proxy at ${CLAUDE_BASE} (${MODEL})`);
// ─── Language detection ────────────────────────────────────────────────────────
function detectLanguage(code, filename) {
    if (filename?.endsWith(".tact"))
        return "tact";
    if (filename?.endsWith(".fc") || filename?.endsWith(".func"))
        return "func";
    if (code.includes("contract ") && code.includes("fun "))
        return "tact";
    if (code.includes("() impure") || code.includes("recv_internal") || code.includes("#include"))
        return "func";
    return "unknown";
}
// ─── Prompts ───────────────────────────────────────────────────────────────────
const SYSTEM_PROMPT = `You are TonAudit AI, an expert TON blockchain smart contract security auditor with deep knowledge of:
- FunC language (TON's primary smart contract language)
- Tact language (TON's newer high-level language)
- TON Virtual Machine (TVM) internals and opcodes
- Common TON-specific vulnerabilities and attack vectors
- TON ecosystem standards (TEP-64, TEP-74 Jettons, TEP-62 NFT)
- Gas optimization patterns for TON

Your analysis must be thorough, precise, and actionable. Always respond with valid JSON matching the specified schema exactly.`;
function buildPrompt(code, language, filename) {
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
// ─── JSON sanitizer ────────────────────────────────────────────────────────────
function parseAuditJSON(raw) {
    const jsonMatch = raw.match(/\{[\s\S]*\}/);
    if (!jsonMatch)
        throw new Error("No JSON found in response. Raw: " + raw.slice(0, 200));
    let jsonStr = jsonMatch[0];
    // Escape literal newlines/tabs inside JSON string values
    jsonStr = jsonStr.replace(/"(?:[^"\\]|\\.)*"/g, (match) => match
        .replace(/\n/g, "\\n")
        .replace(/\r/g, "\\r")
        .replace(/\t/g, "\\t"));
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let parsed;
    try {
        parsed = JSON.parse(jsonStr);
    }
    catch {
        // Last resort: strip all unescaped control chars
        const cleaned = jsonStr.replace(/[\x00-\x1F\x7F]/g, (c) => {
            if (c === "\n")
                return "\\n";
            if (c === "\r")
                return "\\r";
            if (c === "\t")
                return "\\t";
            return "";
        });
        parsed = JSON.parse(cleaned);
    }
    return parsed;
}
// ─── Main audit function ───────────────────────────────────────────────────────
async function auditContract(code, filename, onChunk) {
    const language = detectLanguage(code, filename);
    const lines = code.split("\n").filter((l) => l.trim().length > 0).length;
    let fullResponse = "";
    if (anthropicClient) {
        // ── Anthropic SDK (production) ───────────────────────────────────────────
        const stream = anthropicClient.messages.stream({
            model: MODEL,
            max_tokens: 4096,
            system: SYSTEM_PROMPT,
            messages: [{ role: "user", content: buildPrompt(code, language, filename) }],
        });
        for await (const event of stream) {
            if (event.type === "content_block_delta" &&
                event.delta.type === "text_delta") {
                fullResponse += event.delta.text;
                onChunk?.(event.delta.text);
            }
        }
    }
    else {
        // ── OpenAI-compat proxy (local dev) ──────────────────────────────────────
        const stream = await openaiClient.chat.completions.create({
            model: MODEL,
            max_tokens: 4096,
            stream: true,
            messages: [
                { role: "system", content: SYSTEM_PROMPT },
                { role: "user", content: buildPrompt(code, language, filename) },
            ],
        });
        for await (const chunk of stream) {
            const delta = chunk.choices[0]?.delta?.content || "";
            fullResponse += delta;
            if (delta)
                onChunk?.(delta);
        }
    }
    const parsed = parseAuditJSON(fullResponse);
    const findings = (parsed.findings || []).map(
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (f, i) => ({ ...f, id: `TON-${String(i + 1).padStart(3, "0")}` }));
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
