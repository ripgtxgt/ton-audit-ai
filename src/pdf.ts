import PDFDocument from "pdfkit";
import { AuditReport, Finding } from "./auditor";

// ─── Color palette ────────────────────────────────────────────────────────────
const C = {
  bg:       "#0a0b0f",
  surface:  "#13151f",
  border:   "#252840",
  accent:   "#4f7fff",
  text:     "#e4e6f0",
  muted:    "#6b7298",
  critical: "#ff4d6a",
  high:     "#ff7d3b",
  medium:   "#f5c542",
  low:      "#4ade80",
  info:     "#60c4ff",
  white:    "#ffffff",
};

function hexToRgb(hex: string): [number, number, number] {
  const r = parseInt(hex.slice(1, 3), 16);
  const g = parseInt(hex.slice(3, 5), 16);
  const b = parseInt(hex.slice(5, 7), 16);
  return [r, g, b];
}

function sevColor(severity: string): string {
  return (
    { critical: C.critical, high: C.high, medium: C.medium, low: C.low, info: C.info }[severity] ??
    C.muted
  );
}

function sevLabel(severity: string): string {
  return severity.toUpperCase();
}

// ─── Main export ──────────────────────────────────────────────────────────────

export function generatePDF(report: AuditReport): Promise<Buffer> {
  return new Promise((resolve, reject) => {
  const chunks: Buffer[] = [];
  const doc = new PDFDocument({
    size: "A4",
    margins: { top: 48, bottom: 48, left: 52, right: 52 },
    info: {
      Title: `TonAudit AI — ${report.contractName}`,
      Author: "TonAudit AI",
      Subject: "Smart Contract Security Audit Report",
    },
  });

  doc.on("data", (chunk: Buffer) => chunks.push(chunk));
  doc.on("end", () => resolve(Buffer.concat(chunks)));
  doc.on("error", reject);

  const W = doc.page.width - 104; // usable width

  // ── Cover page ────────────────────────────────────────────────────────────
  // Dark background
  doc.rect(0, 0, doc.page.width, doc.page.height).fill(hexToRgb(C.bg));

  // Accent bar top
  doc.rect(0, 0, doc.page.width, 6).fill(hexToRgb(C.accent));

  // Logo area
  doc.moveDown(4);
  doc
    .fillColor(hexToRgb(C.accent))
    .font("Helvetica-Bold")
    .fontSize(11)
    .text("🔐  TONAUDIT AI", 52, 80, { align: "left" });

  doc
    .fillColor(hexToRgb(C.muted))
    .font("Helvetica")
    .fontSize(9)
    .text("Smart Contract Security Auditor", 52, 96);

  // Divider
  doc.moveTo(52, 116).lineTo(doc.page.width - 52, 116).strokeColor(hexToRgb(C.border)).lineWidth(1).stroke();

  // Title
  doc
    .fillColor(hexToRgb(C.white))
    .font("Helvetica-Bold")
    .fontSize(28)
    .text("Security Audit Report", 52, 148);

  // Contract name
  doc
    .fillColor(hexToRgb(C.accent))
    .font("Helvetica-Bold")
    .fontSize(18)
    .text(report.contractName, 52, 190);

  // Meta grid (2 cols)
  const metaY = 250;
  const metaItems = [
    ["Audit Date",    new Date(report.auditedAt).toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" })],
    ["Language",      report.language === "func" ? "FunC" : report.language === "tact" ? "Tact" : "Unknown"],
    ["Lines of Code", String(report.linesOfCode)],
    ["AI Model",      "Claude Opus"],
  ];
  metaItems.forEach(([label, value], i) => {
    const col = i % 2;
    const row = Math.floor(i / 2);
    const x = 52 + col * (W / 2 + 10);
    const y = metaY + row * 54;
    // Card background
    doc.roundedRect(x, y, W / 2 - 10, 44, 6).fill(hexToRgb(C.surface));
    doc.fillColor(hexToRgb(C.muted)).font("Helvetica").fontSize(8).text(label.toUpperCase(), x + 12, y + 9);
    doc.fillColor(hexToRgb(C.text)).font("Helvetica-Bold").fontSize(12).text(value, x + 12, y + 21);
  });

  // Risk badge
  const riskY = metaY + 130;
  const riskColor = hexToRgb(sevColor(report.overallRisk === "clean" ? "low" : report.overallRisk));
  doc.roundedRect(52, riskY, 180, 52, 8).fill(riskColor);
  doc.fillColor(hexToRgb(C.bg)).font("Helvetica-Bold").fontSize(11).text("OVERALL RISK", 52, riskY + 9, { width: 180, align: "center" });
  doc.fillColor(hexToRgb(C.bg)).font("Helvetica-Bold").fontSize(20).text(report.overallRisk.toUpperCase(), 52, riskY + 24, { width: 180, align: "center" });

  // Security score
  doc.roundedRect(248, riskY, 120, 52, 8).fill(hexToRgb(C.surface));
  doc.fillColor(hexToRgb(C.muted)).font("Helvetica").fontSize(8).text("SECURITY SCORE", 248, riskY + 9, { width: 120, align: "center" });
  const scoreColor = report.score >= 80 ? C.low : report.score >= 60 ? C.medium : report.score >= 40 ? C.high : C.critical;
  doc.fillColor(hexToRgb(scoreColor)).font("Helvetica-Bold").fontSize(22).text(`${report.score}/100`, 248, riskY + 22, { width: 120, align: "center" });

  // Findings count summary
  const counts: Record<string, number> = {};
  report.findings.forEach((f) => { counts[f.severity] = (counts[f.severity] ?? 0) + 1; });
  const countY = riskY + 72;
  const sevs = ["critical", "high", "medium", "low", "info"];
  sevs.forEach((sev, i) => {
    const x = 52 + i * (W / 5);
    const count = counts[sev] ?? 0;
    doc.roundedRect(x, countY, W / 5 - 6, 44, 6).fill(hexToRgb(C.surface));
    doc.fillColor(hexToRgb(sevColor(sev))).font("Helvetica-Bold").fontSize(18).text(String(count), x, countY + 6, { width: W / 5 - 6, align: "center" });
    doc.fillColor(hexToRgb(C.muted)).font("Helvetica").fontSize(7).text(sev.toUpperCase(), x, countY + 28, { width: W / 5 - 6, align: "center" });
  });

  // Summary
  const sumY = countY + 64;
  doc.roundedRect(52, sumY, W, 90, 8).fill(hexToRgb(C.surface));
  doc.fillColor(hexToRgb(C.accent)).font("Helvetica-Bold").fontSize(9).text("EXECUTIVE SUMMARY", 64, sumY + 12);
  doc.fillColor(hexToRgb(C.text)).font("Helvetica").fontSize(10).text(report.summary, 64, sumY + 26, { width: W - 24, lineGap: 4 });

  // Footer
  doc.moveTo(52, doc.page.height - 60).lineTo(doc.page.width - 52, doc.page.height - 60).strokeColor(hexToRgb(C.border)).lineWidth(1).stroke();
  doc.fillColor(hexToRgb(C.muted)).font("Helvetica").fontSize(8).text(
    "TonAudit AI  ·  github.com/ripgtxgt/ton-audit-ai  ·  Built for TokenTon26 Hackathon",
    52, doc.page.height - 46, { align: "center", width: W }
  );

  // ── Findings pages ────────────────────────────────────────────────────────
  doc.addPage({ size: "A4", margins: { top: 48, bottom: 48, left: 52, right: 52 } });
  doc.rect(0, 0, doc.page.width, doc.page.height).fill(hexToRgb(C.bg));
  doc.rect(0, 0, doc.page.width, 6).fill(hexToRgb(C.accent));

  // Section header
  doc.fillColor(hexToRgb(C.white)).font("Helvetica-Bold").fontSize(20).text("Security Findings", 52, 32);
  doc.fillColor(hexToRgb(C.muted)).font("Helvetica").fontSize(10)
    .text(`${report.findings.length} issues identified  ·  ${report.contractName}`, 52, 56);
  doc.moveTo(52, 76).lineTo(doc.page.width - 52, 76).strokeColor(hexToRgb(C.border)).lineWidth(1).stroke();

  let y = 92;
  const PAGE_BOTTOM = doc.page.height - 60;

  for (let i = 0; i < report.findings.length; i++) {
    const f: Finding = report.findings[i];
    const color = hexToRgb(sevColor(f.severity));

    // Estimate card height
    const descLines = Math.ceil(f.description.length / 90) + 1;
    const recLines  = Math.ceil(f.recommendation.length / 90) + 1;
    const cardH = 16 + 20 + descLines * 13 + 8 + recLines * 13 + (f.codeSnippet ? 28 : 0) + 20;

    if (y + cardH > PAGE_BOTTOM) {
      doc.addPage({ size: "A4", margins: { top: 48, bottom: 48, left: 52, right: 52 } });
      doc.rect(0, 0, doc.page.width, doc.page.height).fill(hexToRgb(C.bg));
      doc.rect(0, 0, doc.page.width, 4).fill(hexToRgb(C.accent));
      y = 40;
    }

    // Card bg
    doc.roundedRect(52, y, W, cardH, 8).fill(hexToRgb(C.surface));
    // Severity accent bar
    doc.roundedRect(52, y, 4, cardH, 2).fill(color);

    // Header row: id + severity badge + title
    const headerY = y + 12;
    doc.fillColor(hexToRgb(C.muted)).font("Helvetica-Bold").fontSize(8).text(f.id, 64, headerY);
    // Severity pill
    const pilW = 58;
    doc.roundedRect(64 + 38, headerY - 2, pilW, 14, 4).fill(color);
    doc.fillColor(hexToRgb(C.bg)).font("Helvetica-Bold").fontSize(7).text(sevLabel(f.severity), 64 + 38, headerY + 2, { width: pilW, align: "center" });
    // Category
    doc.fillColor(hexToRgb(C.muted)).font("Helvetica").fontSize(8).text(f.category, 64 + 38 + pilW + 8, headerY);

    // Title
    doc.fillColor(hexToRgb(C.white)).font("Helvetica-Bold").fontSize(11)
      .text(f.title, 64, headerY + 16, { width: W - 28 });

    // Location
    let bodyY = headerY + 16 + 16;
    if (f.location) {
      doc.fillColor(hexToRgb(C.info)).font("Helvetica").fontSize(8)
        .text(`📍 ${f.location}`, 64, bodyY);
      bodyY += 14;
    }

    // Description
    doc.fillColor(hexToRgb(C.muted)).font("Helvetica").fontSize(8)
      .text("DESCRIPTION", 64, bodyY);
    bodyY += 11;
    doc.fillColor(hexToRgb(C.text)).font("Helvetica").fontSize(9)
      .text(f.description, 64, bodyY, { width: W - 28, lineGap: 2 });
    bodyY += descLines * 13 + 2;

    // Code snippet
    if (f.codeSnippet) {
      doc.roundedRect(64, bodyY, W - 28, 20, 4).fill(hexToRgb(C.bg));
      doc.fillColor(hexToRgb("#a8b4ff")).font("Courier").fontSize(7.5)
        .text(f.codeSnippet.slice(0, 120), 72, bodyY + 6, { width: W - 44, lineBreak: false });
      bodyY += 26;
    }

    // Recommendation
    doc.fillColor(hexToRgb(C.low)).font("Helvetica-Bold").fontSize(8)
      .text("RECOMMENDATION", 64, bodyY);
    bodyY += 11;
    doc.fillColor(hexToRgb(C.text)).font("Helvetica").fontSize(9)
      .text(f.recommendation, 64, bodyY, { width: W - 28, lineGap: 2 });

    y += cardH + 10;
  }

  // ── Analysis page ─────────────────────────────────────────────────────────
  doc.addPage({ size: "A4", margins: { top: 48, bottom: 48, left: 52, right: 52 } });
  doc.rect(0, 0, doc.page.width, doc.page.height).fill(hexToRgb(C.bg));
  doc.rect(0, 0, doc.page.width, 4).fill(hexToRgb(C.accent));

  doc.fillColor(hexToRgb(C.white)).font("Helvetica-Bold").fontSize(20).text("Analysis", 52, 32);
  doc.moveTo(52, 62).lineTo(doc.page.width - 52, 62).strokeColor(hexToRgb(C.border)).lineWidth(1).stroke();

  // Gas analysis card
  doc.roundedRect(52, 76, W, 8 + Math.ceil(report.gasAnalysis.length / 88) * 13 + 40, 8)
    .fill(hexToRgb(C.surface));
  doc.fillColor(hexToRgb(C.accent)).font("Helvetica-Bold").fontSize(10).text("⛽  GAS ANALYSIS", 64, 90);
  doc.fillColor(hexToRgb(C.text)).font("Helvetica").fontSize(10)
    .text(report.gasAnalysis, 64, 108, { width: W - 24, lineGap: 3 });

  const gasCardH = 8 + Math.ceil(report.gasAnalysis.length / 88) * 13 + 40;
  const archY = 76 + gasCardH + 16;

  // Architecture notes card
  doc.roundedRect(52, archY, W, 8 + Math.ceil(report.architectureNotes.length / 88) * 13 + 40, 8)
    .fill(hexToRgb(C.surface));
  doc.fillColor(hexToRgb(C.accent)).font("Helvetica-Bold").fontSize(10).text("🏗️  ARCHITECTURE NOTES", 64, archY + 14);
  doc.fillColor(hexToRgb(C.text)).font("Helvetica").fontSize(10)
    .text(report.architectureNotes, 64, archY + 32, { width: W - 24, lineGap: 3 });

  // Final footer on every page handled by pdfkit event would need post-processing;
  // simpler to just add footer on last page
  doc.fillColor(hexToRgb(C.muted)).font("Helvetica").fontSize(8).text(
    "TonAudit AI  ·  github.com/ripgtxgt/ton-audit-ai  ·  Built for TokenTon26 Hackathon",
    52, doc.page.height - 36, { align: "center", width: W }
  );

  doc.end();
  }); // end Promise
}
