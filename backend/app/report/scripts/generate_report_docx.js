/*
 * Genera el informe pericial en formato .docx a partir del JSON
 * producido por app/report/report_generator.py (report_to_json).
 *
 * Uso:  node generate_report_docx.js <report_data.json> <salida.docx>
 */

const fs = require("fs");
const {
  Document, Packer, Paragraph, TextRun, HeadingLevel,
  Table, TableRow, TableCell, WidthType, ShadingType,
  BorderStyle, AlignmentType,
} = require("docx");

const [, , inputPath, outputPath] = process.argv;
if (!inputPath || !outputPath) {
  console.error("Uso: node generate_report_docx.js <report_data.json> <salida.docx>");
  process.exit(1);
}

const data = JSON.parse(fs.readFileSync(inputPath, "utf-8"));

const LABEL_TEXT = { 0: "Tráfico normal", 1: "Actividad potencialmente maliciosa" };

function hr() {
  return new Paragraph({
    border: { bottom: { style: BorderStyle.SINGLE, size: 6, color: "999999" } },
    spacing: { after: 200 },
  });
}

function kvParagraph(label, value) {
  return new Paragraph({
    children: [
      new TextRun({ text: `${label}: `, bold: true }),
      new TextRun({ text: String(value ?? "n/d") }),
    ],
    spacing: { after: 80 },
  });
}

// ---------------- Resumen ejecutivo ----------------

const nMalicious = data.findings.filter(f => f.prediction.label === 1).length;
const nNormal = data.findings.length - nMalicious;
const custodyValid = data.custody_verification && data.custody_verification.valid;

const execSummary = [
  new Paragraph({ text: "Informe Pericial", heading: HeadingLevel.TITLE }),
  new Paragraph({
    text: `Caso: ${data.case_id}`,
    heading: HeadingLevel.HEADING_2,
  }),
  new Paragraph({
    children: [new TextRun({ text: `Generado con MODEXRE — fuente: ${data.source_name}`, italics: true, color: "666666" })],
    spacing: { after: 300 },
  }),
  hr(),
  new Paragraph({ text: "Resumen Ejecutivo", heading: HeadingLevel.HEADING_1 }),
  new Paragraph({
    text: `Se ha analizado el tráfico de red correspondiente a la fuente "${data.source_name}" ` +
      `(fichero: "${data.file_path}"), aplicando un sistema automatizado de detección de intrusiones ` +
      `basado en inteligencia artificial (XGBoost), cuyas decisiones han sido interpretadas mediante ` +
      `técnicas de IA explicable (SHAP).`,
    spacing: { after: 200 },
  }),
  new Paragraph({
    children: [
      new TextRun({ text: `Del total de ${data.findings.length} eventos analizados, ` }),
      new TextRun({ text: `${nMalicious}`, bold: true }),
      new TextRun({ text: ` se han clasificado como actividad potencialmente maliciosa y ` }),
      new TextRun({ text: `${nNormal}`, bold: true }),
      new TextRun({ text: ` como tráfico normal.` }),
    ],
    spacing: { after: 200 },
  }),
  new Paragraph({
    children: [
      new TextRun({
        text: custodyValid
          ? "La cadena de custodia del caso ha sido verificada matemáticamente y no presenta indicios de alteración."
          : "ADVERTENCIA: la verificación de la cadena de custodia ha detectado posibles inconsistencias.",
        bold: !custodyValid,
        color: custodyValid ? "1a7a1a" : "b00020",
      }),
    ],
    spacing: { after: 300 },
  }),
];

// ---------------- Anexo técnico: metodología ----------------

const methodology = [
  new Paragraph({ text: "Anexo Técnico", heading: HeadingLevel.HEADING_1 }),
  new Paragraph({ text: "Metodología", heading: HeadingLevel.HEADING_2 }),
  kvParagraph("Fuente de datos", data.source_name),
  kvParagraph("Normalización", "OCSF (Open Cybersecurity Schema Framework), clase Detection Finding (class_uid=2004)"),
  kvParagraph("Modelo", "XGBoost, entrenado y congelado en modo Laboratorio; usado exclusivamente en modo inferencia en este caso"),
  kvParagraph("Explicabilidad", "SHAP (TreeExplainer), explicación local por evento"),
  new Paragraph({ text: "", spacing: { after: 100 } }),
];

// ---------------- Anexo técnico: hallazgos ----------------

const findingsSection = [new Paragraph({ text: "Resultados por evento", heading: HeadingLevel.HEADING_2 })];

data.findings.forEach((f, i) => {
  const pred = f.prediction;
  const src = f.src_endpoint || {};
  const dst = f.dst_endpoint || {};

  findingsSection.push(new Paragraph({ text: `Evento #${i + 1}`, heading: HeadingLevel.HEADING_3 }));
  findingsSection.push(kvParagraph(
    "Clasificación del modelo",
    `${LABEL_TEXT[pred.label] ?? "Desconocido"} (probabilidad: ${pred.probability.toFixed(3)}, modelo: ${pred.model_version})`
  ));
  if (f.finding_info && f.finding_info.title) {
    findingsSection.push(kvParagraph(
      "Alerta original del IDS",
      `${f.finding_info.title} (categoría: ${(f.finding_info.types || []).join(", ") || "n/d"})`
    ));
  }
  findingsSection.push(kvParagraph(
    "Origen → Destino",
    `${src.ip ?? "n/d"}:${src.port ?? "n/d"} → ${dst.ip ?? "n/d"}:${dst.port ?? "n/d"}`
  ));

  findingsSection.push(new Paragraph({
    children: [new TextRun({ text: "Variables más influyentes en la decisión (SHAP):", bold: true })],
    spacing: { before: 100, after: 60 },
  }));

  const shapRows = [
    new TableRow({
      children: [
        new TableCell({ width: { size: 60, type: WidthType.PERCENTAGE }, shading: { type: ShadingType.CLEAR, fill: "EEEEEE" }, children: [new Paragraph({ children: [new TextRun({ text: "Variable", bold: true })] })] }),
        new TableCell({ width: { size: 40, type: WidthType.PERCENTAGE }, shading: { type: ShadingType.CLEAR, fill: "EEEEEE" }, children: [new Paragraph({ children: [new TextRun({ text: "Valor SHAP", bold: true })] })] }),
      ],
    }),
    ...f.explanation.top_features.map(feat => new TableRow({
      children: [
        new TableCell({ width: { size: 60, type: WidthType.PERCENTAGE }, children: [new Paragraph(feat.feature)] }),
        new TableCell({ width: { size: 40, type: WidthType.PERCENTAGE }, children: [new Paragraph((feat.shap_value >= 0 ? "+" : "") + feat.shap_value.toFixed(4))] }),
      ],
    })),
  ];

  findingsSection.push(new Table({
    width: { size: 100, type: WidthType.PERCENTAGE },
    columnWidths: [6000, 4000],
    rows: shapRows,
  }));
  findingsSection.push(new Paragraph({ text: "", spacing: { after: 200 } }));
});

// ---------------- Anexo técnico: cadena de custodia ----------------

const custodySection = [
  new Paragraph({ text: "Cadena de Custodia", heading: HeadingLevel.HEADING_2 }),
  kvParagraph("Total de eslabones registrados", data.custody_verification.total_records),
  kvParagraph("Íntegra", data.custody_verification.valid ? "Sí" : "NO — ver incidencias"),
];

if (data.custody_verification.issues && data.custody_verification.issues.length > 0) {
  custodySection.push(new Paragraph({ text: "Incidencias detectadas:", spacing: { before: 100, after: 60 } }));
  data.custody_verification.issues.forEach(issue => {
    custodySection.push(new Paragraph({ text: `• ${issue}`, spacing: { after: 60 } }));
  });
}

custodySection.push(new Paragraph({ text: "", spacing: { after: 100 } }));
custodySection.push(new Paragraph({ text: "Detalle de eslabones", heading: HeadingLevel.HEADING_3 }));

const chainHeaderRow = new TableRow({
  children: ["#", "Operación", "Componente", "Hash del eslabón (16 primeros caracteres)"].map(h =>
    new TableCell({
      shading: { type: ShadingType.CLEAR, fill: "EEEEEE" },
      children: [new Paragraph({ children: [new TextRun({ text: h, bold: true })] })],
    })
  ),
});

const chainRows = data.custody_chain.map(rec => new TableRow({
  children: [
    new TableCell({ children: [new Paragraph(String(rec.index))] }),
    new TableCell({ children: [new Paragraph(rec.operation)] }),
    new TableCell({ children: [new Paragraph(rec.component)] }),
    new TableCell({ children: [new Paragraph(rec.record_hash.slice(0, 16) + "...")] }),
  ],
}));

custodySection.push(new Table({
  width: { size: 100, type: WidthType.PERCENTAGE },
  columnWidths: [700, 2300, 4500, 2500],
  rows: [chainHeaderRow, ...chainRows],
}));

// ---------------- Ensamblado del documento ----------------

const doc = new Document({
  sections: [
    {
      properties: { page: { size: { width: 11906, height: 16838 } } }, // A4
      children: [
        ...execSummary,
        ...methodology,
        ...findingsSection,
        ...custodySection,
      ],
    },
  ],
});

Packer.toBuffer(doc).then(buffer => {
  fs.writeFileSync(outputPath, buffer);
  console.log(`Informe generado: ${outputPath}`);
});
