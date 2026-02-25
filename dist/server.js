"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const multer_1 = __importDefault(require("multer"));
const cors_1 = __importDefault(require("cors"));
const path_1 = __importDefault(require("path"));
const fs_1 = __importDefault(require("fs"));
const dotenv_1 = __importDefault(require("dotenv"));
const auditor_1 = require("./auditor");
const pdf_1 = require("./pdf");
dotenv_1.default.config();
// Uses local claude-max proxy at http://localhost:8317/v1 (OpenAI-compatible)
// No API key needed — relies on openclaw gateway auth
const app = (0, express_1.default)();
const PORT = process.env.PORT || 3000;
app.use((0, cors_1.default)());
app.use(express_1.default.json({ limit: "1mb" }));
app.use(express_1.default.static(path_1.default.join(__dirname, "../public")));
// Multer: accept .fc, .func, .tact files up to 100KB
const upload = (0, multer_1.default)({
    storage: multer_1.default.memoryStorage(),
    limits: { fileSize: 100 * 1024 },
    fileFilter: (_req, file, cb) => {
        const allowed = [".fc", ".func", ".tact"];
        const ext = path_1.default.extname(file.originalname).toLowerCase();
        if (allowed.includes(ext)) {
            cb(null, true);
        }
        else {
            cb(new Error(`Only ${allowed.join(", ")} files allowed`));
        }
    },
});
// Load sample contracts
const SAMPLES_DIR = path_1.default.join(__dirname, "samples");
function getSamples() {
    const samples = {};
    if (fs_1.default.existsSync(SAMPLES_DIR)) {
        for (const file of fs_1.default.readdirSync(SAMPLES_DIR)) {
            const ext = path_1.default.extname(file);
            if ([".fc", ".func", ".tact"].includes(ext)) {
                samples[file] = fs_1.default.readFileSync(path_1.default.join(SAMPLES_DIR, file), "utf-8");
            }
        }
    }
    return samples;
}
// ── Routes ────────────────────────────────────────────────────────────────────
app.get("/api/health", (_req, res) => {
    res.json({ status: "ok", model: "claude-opus-4-5-20251101", version: "1.0.0" });
});
app.get("/api/samples", (_req, res) => {
    const samples = getSamples();
    res.json({
        samples: Object.keys(samples).map((name) => ({
            name,
            lines: samples[name].split("\n").length,
            preview: samples[name].split("\n").slice(0, 3).join("\n"),
        })),
    });
});
app.get("/api/samples/:name", (req, res) => {
    const samples = getSamples();
    const { name } = req.params;
    if (!samples[name]) {
        return res.status(404).json({ error: "Sample not found" });
    }
    res.json({ name, code: samples[name] });
});
// Main audit endpoint — code pasted as JSON
app.post("/api/audit", async (req, res) => {
    const { code, filename } = req.body;
    if (!code || code.trim().length < 10) {
        return res.status(400).json({ error: "Contract code is required (min 10 chars)" });
    }
    if (code.length > 80000) {
        return res.status(400).json({ error: "Contract too large (max 80KB)" });
    }
    // Stream SSE so the UI can show live progress
    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache");
    res.setHeader("Connection", "keep-alive");
    res.flushHeaders();
    const send = (event, data) => {
        res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
    };
    send("status", { message: "🔍 Analyzing contract structure..." });
    try {
        let chunkCount = 0;
        const report = await (0, auditor_1.auditContract)(code, filename, (_chunk) => {
            chunkCount++;
            // Send progress updates every 10 chunks
            if (chunkCount % 10 === 0) {
                send("progress", { message: "⚙️ Running security checks..." });
            }
        });
        send("status", { message: "✅ Audit complete" });
        send("report", report);
        res.write("event: done\ndata: {}\n\n");
    }
    catch (err) {
        send("error", { message: err instanceof Error ? err.message : "Audit failed" });
    }
    finally {
        res.end();
    }
});
// File upload audit endpoint
app.post("/api/audit/upload", upload.single("contract"), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: "No file uploaded" });
    }
    const code = req.file.buffer.toString("utf-8");
    const filename = req.file.originalname;
    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache");
    res.setHeader("Connection", "keep-alive");
    res.flushHeaders();
    const send = (event, data) => {
        res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
    };
    send("status", { message: `🔍 Analyzing ${filename}...` });
    try {
        const report = await (0, auditor_1.auditContract)(code, filename, () => { });
        send("status", { message: "✅ Audit complete" });
        send("report", report);
        res.write("event: done\ndata: {}\n\n");
    }
    catch (err) {
        send("error", { message: err instanceof Error ? err.message : "Audit failed" });
    }
    finally {
        res.end();
    }
});
// ── Batch audit (multi-file upload) ──────────────────────────────────────────
// Accepts up to 10 contract files, audits sequentially, returns a comparison
// report summarising findings across all contracts.
const batchUpload = (0, multer_1.default)({
    storage: multer_1.default.memoryStorage(),
    limits: { fileSize: 100 * 1024, files: 10 },
    fileFilter: (_req, file, cb) => {
        const allowed = [".fc", ".func", ".tact"];
        const ext = path_1.default.extname(file.originalname).toLowerCase();
        if (allowed.includes(ext))
            cb(null, true);
        else
            cb(new Error(`Only ${allowed.join(", ")} files allowed`));
    },
});
function buildComparison(reports) {
    const riskRanking = reports
        .map((r) => ({ contractName: r.contractName, score: r.score, overallRisk: r.overallRisk }))
        .sort((a, b) => a.score - b.score);
    const allFindings = reports.flatMap((r) => r.findings);
    const catCounts = {};
    for (const f of allFindings) {
        catCounts[f.category] = (catCounts[f.category] ?? 0) + 1;
    }
    const commonCategories = Object.entries(catCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5)
        .map(([category, count]) => ({ category, count }));
    return {
        riskRanking,
        totalFindings: allFindings.length,
        criticalCount: allFindings.filter((f) => f.severity === "critical").length,
        highCount: allFindings.filter((f) => f.severity === "high").length,
        mostVulnerable: riskRanking[0]?.contractName ?? "—",
        safest: riskRanking[riskRanking.length - 1]?.contractName ?? "—",
        commonCategories,
    };
}
app.post("/api/audit/batch", batchUpload.array("contracts", 10), async (req, res) => {
    const files = req.files;
    if (!files || files.length === 0) {
        return res.status(400).json({ error: "No files uploaded" });
    }
    if (files.length < 2) {
        return res.status(400).json({ error: "Batch audit requires at least 2 contracts" });
    }
    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache");
    res.setHeader("Connection", "keep-alive");
    res.flushHeaders();
    const send = (event, data) => res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
    const reports = [];
    for (let i = 0; i < files.length; i++) {
        const file = files[i];
        const filename = file.originalname;
        const code = file.buffer.toString("utf-8");
        send("progress", {
            message: `🔍 Auditing ${filename} (${i + 1}/${files.length})…`,
            current: i + 1,
            total: files.length,
            filename,
        });
        try {
            const report = await (0, auditor_1.auditContract)(code, filename, () => { });
            reports.push(report);
            send("partial", { index: i, filename, score: report.score, risk: report.overallRisk });
        }
        catch (err) {
            send("partial_error", {
                index: i,
                filename,
                error: err instanceof Error ? err.message : "Audit failed",
            });
        }
    }
    if (reports.length === 0) {
        send("error", { message: "All audits failed" });
        return res.end();
    }
    const batchReport = {
        auditedAt: new Date().toISOString(),
        totalContracts: files.length,
        reports,
        comparison: buildComparison(reports),
    };
    send("batch_report", batchReport);
    res.write("event: done\ndata: {}\n\n");
    res.end();
});
// PDF generation endpoint — accepts completed report JSON, returns PDF
app.post("/api/report/pdf", async (req, res) => {
    const report = req.body;
    if (!report?.contractName || !Array.isArray(report?.findings)) {
        return res.status(400).json({ error: "Invalid report object" });
    }
    try {
        const pdf = await (0, pdf_1.generatePDF)(report);
        const filename = `tonaudit-${report.contractName.replace(/[^a-zA-Z0-9_-]/g, "_")}.pdf`;
        res.setHeader("Content-Type", "application/pdf");
        res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
        res.setHeader("Content-Length", pdf.length);
        res.end(pdf);
    }
    catch (err) {
        res.status(500).json({ error: err instanceof Error ? err.message : "PDF generation failed" });
    }
});
// Batch PDF — generates a combined PDF for all reports in a batch
app.post("/api/report/batch-pdf", async (req, res) => {
    const { reports } = req.body;
    if (!Array.isArray(reports) || reports.length === 0) {
        return res.status(400).json({ error: "reports array required" });
    }
    try {
        // Generate individual PDFs and concatenate via raw buffer concat
        // (simple approach: just use first report's PDF for now, proper merge needs pdf-lib)
        const pdfBuffers = await Promise.all(reports.map((r) => (0, pdf_1.generatePDF)(r)));
        // For simplicity, return a zip-like response with the first PDF
        // TODO: use pdf-lib to merge — for now return the most critical contract's PDF
        const sorted = [...reports].sort((a, b) => a.score - b.score);
        const worstReport = sorted[0];
        const worstPdf = await (0, pdf_1.generatePDF)(worstReport);
        const filename = `tonaudit-batch-${reports.length}contracts.pdf`;
        res.setHeader("Content-Type", "application/pdf");
        res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
        res.end(worstPdf);
    }
    catch (err) {
        res.status(500).json({ error: err instanceof Error ? err.message : "PDF failed" });
    }
});
app.listen(PORT, () => {
    console.log(`\n⚡ TonAudit AI running at http://localhost:${PORT}`);
    console.log(`   Model: claude-opus-4-5-20251101`);
    console.log(`   Samples: ${Object.keys(getSamples()).length} contracts loaded\n`);
});
