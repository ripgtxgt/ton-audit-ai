"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.detectLanguage = detectLanguage;
exports.auditContract = auditContract;
const openai_1 = __importDefault(require("openai"));
// Use claude-max local proxy (OpenAI-compatible)
const client = new openai_1.default({
    baseURL: process.env.CLAUDE_API_BASE || "http://localhost:8317/v1",
    apiKey: process.env.CLAUDE_API_KEY || "claude-max",
});
const MODEL = process.env.AUDIT_MODEL || "claude-opus-4-5-20251101";
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
const AUDIT_SYSTEM_PROMPT = `You are TonAudit AI, an expert TON blockchain smart contract security auditor with deep knowledge of:
- FunC language (TON's primary smart contract language)
- Tact language (TON's newer high-level language)
- TON Virtual Machine (TVM) internals and opcodes
- Common TON-specific vulnerabilities and attack vectors
- TON ecosystem standards (TEP-64, TEP-74 Jettons, TEP-62 NFT)
- Gas optimization patterns for TON

Your analysis must be thorough, precise, and actionable. Always respond with valid JSON matching the specified schema exactly.`;
function buildAuditPrompt(code, language, filename) {
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

Respond ONLY with valid JSON in this exact schema:
{
  "overallRisk": "critical|high|medium|low|clean",
  "summary": "2-3 sentence executive summary of the contract's purpose and security posture",
  "score": <integer 0-100, where 100 is perfectly secure>,
  "findings": [
    {
      "severity": "critical|high|medium|low|info",
      "category": "category name",
      "title": "short title",
      "description": "detailed description of the vulnerability and why it matters",
      "location": "function name or line reference if identifiable",
      "recommendation": "specific, actionable fix with code example if applicable",
      "codeSnippet": "relevant code snippet showing the issue (optional, omit if not helpful)"
    }
  ],
  "gasAnalysis": "Analysis of gas usage patterns, efficiency, and any gas-related risks",
  "architectureNotes": "Notes on contract architecture, design patterns used, and overall code quality"
}

If no findings in a severity level, omit those entries. Order findings by severity (critical first). Keep descriptions concise but complete.`;
}
async function auditContract(code, filename, onChunk) {
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
        if (delta)
            onChunk?.(delta);
    }
    // Parse JSON — Claude sometimes wraps in markdown code fences
    const jsonMatch = fullResponse.match(/\{[\s\S]*\}/);
    if (!jsonMatch) {
        throw new Error("Failed to parse audit response as JSON. Raw: " + fullResponse.slice(0, 200));
    }
    const parsed = JSON.parse(jsonMatch[0]);
    const findings = (parsed.findings || []).map((f, i) => ({
        ...f,
        id: `TON-${String(i + 1).padStart(3, "0")}`,
    }));
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
