import express, { Request, Response } from "express";
import multer from "multer";
import cors from "cors";
import path from "path";
import fs from "fs";
import dotenv from "dotenv";
import { auditContract, AuditReport } from "./auditor";

dotenv.config();

// Uses local claude-max proxy at http://localhost:8317/v1 (OpenAI-compatible)
// No API key needed — relies on openclaw gateway auth

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json({ limit: "1mb" }));
app.use(express.static(path.join(__dirname, "../public")));

// Multer: accept .fc, .func, .tact files up to 100KB
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 100 * 1024 },
  fileFilter: (_req, file, cb) => {
    const allowed = [".fc", ".func", ".tact"];
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowed.includes(ext)) {
      cb(null, true);
    } else {
      cb(new Error(`Only ${allowed.join(", ")} files allowed`));
    }
  },
});

// Load sample contracts
const SAMPLES_DIR = path.join(__dirname, "samples");
function getSamples(): Record<string, string> {
  const samples: Record<string, string> = {};
  if (fs.existsSync(SAMPLES_DIR)) {
    for (const file of fs.readdirSync(SAMPLES_DIR)) {
      const ext = path.extname(file);
      if ([".fc", ".func", ".tact"].includes(ext)) {
        samples[file] = fs.readFileSync(path.join(SAMPLES_DIR, file), "utf-8");
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
app.post("/api/audit", async (req: Request, res: Response) => {
  const { code, filename } = req.body as { code?: string; filename?: string };

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

  const send = (event: string, data: unknown) => {
    res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  };

  send("status", { message: "🔍 Analyzing contract structure..." });

  try {
    let chunkCount = 0;
    const report = await auditContract(code, filename, (_chunk) => {
      chunkCount++;
      // Send progress updates every 10 chunks
      if (chunkCount % 10 === 0) {
        send("progress", { message: "⚙️ Running security checks..." });
      }
    });

    send("status", { message: "✅ Audit complete" });
    send("report", report);
    res.write("event: done\ndata: {}\n\n");
  } catch (err) {
    send("error", { message: err instanceof Error ? err.message : "Audit failed" });
  } finally {
    res.end();
  }
});

// File upload audit endpoint
app.post("/api/audit/upload", upload.single("contract"), async (req: Request, res: Response) => {
  if (!req.file) {
    return res.status(400).json({ error: "No file uploaded" });
  }

  const code = req.file.buffer.toString("utf-8");
  const filename = req.file.originalname;

  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.flushHeaders();

  const send = (event: string, data: unknown) => {
    res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  };

  send("status", { message: `🔍 Analyzing ${filename}...` });

  try {
    const report = await auditContract(code, filename, () => {});
    send("status", { message: "✅ Audit complete" });
    send("report", report);
    res.write("event: done\ndata: {}\n\n");
  } catch (err) {
    send("error", { message: err instanceof Error ? err.message : "Audit failed" });
  } finally {
    res.end();
  }
});

app.listen(PORT, () => {
  console.log(`\n⚡ TonAudit AI running at http://localhost:${PORT}`);
  console.log(`   Model: claude-opus-4-5-20251101`);
  console.log(`   Samples: ${Object.keys(getSamples()).length} contracts loaded\n`);
});
