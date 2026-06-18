const {
  Document,
  Packer,
  Paragraph,
  TextRun,
  Table,
  TableRow,
  TableCell,
  HeadingLevel,
  AlignmentType,
  BorderStyle,
  WidthType,
  ShadingType,
  LevelFormat,
  Header,
  Footer,
  TabStopType,
  TabStopPosition,
  PageBreak,
} = require("docx");
const fs = require("fs");

// ─── Colour palette ────────────────────────────────────────────────────────
const BLUE = "1F4E79";
const BLUE_DARK = "17375E";
const BLUE_LIGHT = "D6E4F0";
const BLUE_MID = "BDD7EE";
const GREY_LIGHT = "F2F2F2";
const GREY_MED = "D9D9D9";
const WHITE = "FFFFFF";
const BLACK = "000000";
const GREEN = "375623";
const GREEN_BG = "E2EFDA";
const RED_BG = "FCE4D6";
const RED_TEXT = "843C0C";
const AMBER_BG = "FFF2CC";
const AMBER_TEXT = "7F6000";

// ─── Helpers ───────────────────────────────────────────────────────────────
const border = (color = GREY_MED) => ({
  style: BorderStyle.SINGLE,
  size: 1,
  color,
});
const borders = (color = GREY_MED) => ({
  top: border(color),
  bottom: border(color),
  left: border(color),
  right: border(color),
});
const noBorder = () => ({ style: BorderStyle.NONE, size: 0, color: WHITE });
const noBorders = () => ({
  top: noBorder(),
  bottom: noBorder(),
  left: noBorder(),
  right: noBorder(),
});
const cellMargins = { top: 100, bottom: 100, left: 140, right: 140 };
const cellMarginsWide = { top: 120, bottom: 120, left: 160, right: 160 };

function h1(text) {
  return new Paragraph({
    heading: HeadingLevel.HEADING_1,
    spacing: { before: 360, after: 160 },
    children: [
      new TextRun({ text, bold: true, font: "Arial", size: 32, color: WHITE }),
    ],
    shading: { fill: BLUE_DARK, type: ShadingType.CLEAR },
    indent: { left: 200, right: 200 },
    border: { bottom: { style: BorderStyle.SINGLE, size: 4, color: BLUE } },
  });
}

function h2(text) {
  return new Paragraph({
    heading: HeadingLevel.HEADING_2,
    spacing: { before: 320, after: 120 },
    children: [
      new TextRun({ text, bold: true, font: "Arial", size: 26, color: WHITE }),
    ],
    shading: { fill: BLUE, type: ShadingType.CLEAR },
    indent: { left: 120 },
  });
}

function h3(text) {
  return new Paragraph({
    heading: HeadingLevel.HEADING_3,
    spacing: { before: 240, after: 100 },
    border: {
      bottom: { style: BorderStyle.SINGLE, size: 2, color: BLUE_MID, space: 2 },
    },
    children: [
      new TextRun({ text, bold: true, font: "Arial", size: 24, color: BLUE }),
    ],
  });
}

function h4(text) {
  return new Paragraph({
    heading: HeadingLevel.HEADING_4,
    spacing: { before: 180, after: 80 },
    children: [
      new TextRun({
        text,
        bold: true,
        font: "Arial",
        size: 22,
        color: BLUE_DARK,
        italics: true,
      }),
    ],
  });
}

function para(text, opts = {}) {
  return new Paragraph({
    spacing: { before: 80, after: 80 },
    children: [new TextRun({ text, font: "Arial", size: 20, ...opts })],
  });
}

function paraRuns(runs, opts = {}) {
  return new Paragraph({
    spacing: { before: 80, after: 80 },
    ...opts,
    children: runs,
  });
}

function code(text) {
  return new TextRun({ text, font: "Courier New", size: 18, color: "C7254E" });
}

function bullet(text, level = 0, numbRef = "bullets") {
  return new Paragraph({
    numbering: { reference: numbRef, level },
    spacing: { before: 60, after: 60 },
    children: [new TextRun({ text, font: "Arial", size: 20 })],
  });
}

function bulletRuns(runs, level = 0) {
  return new Paragraph({
    numbering: { reference: "bullets", level },
    spacing: { before: 60, after: 60 },
    children: runs,
  });
}

function numbered(text, level = 0) {
  return bullet(text, level, "numbers");
}

function spacer(lines = 1) {
  return new Paragraph({
    spacing: { before: lines * 80, after: 0 },
    children: [new TextRun("")],
  });
}

function pageBreak() {
  return new Paragraph({ children: [new PageBreak()] });
}

function infoBox(label, text, bgColor = BLUE_LIGHT, labelColor = BLUE) {
  const W = 9360;
  return new Table({
    width: { size: W, type: WidthType.DXA },
    columnWidths: [W],
    rows: [
      new TableRow({
        children: [
          new TableCell({
            borders: borders(BLUE_MID),
            width: { size: W, type: WidthType.DXA },
            shading: { fill: bgColor, type: ShadingType.CLEAR },
            margins: cellMarginsWide,
            children: [
              new Paragraph({
                spacing: { before: 0, after: 60 },
                children: [
                  new TextRun({
                    text: label,
                    bold: true,
                    font: "Arial",
                    size: 20,
                    color: labelColor,
                  }),
                ],
              }),
              new Paragraph({
                spacing: { before: 0, after: 0 },
                children: [new TextRun({ text, font: "Arial", size: 20 })],
              }),
            ],
          }),
        ],
      }),
    ],
  });
}

function codeBlock(lines) {
  const text = Array.isArray(lines) ? lines.join("\n") : lines;
  const W = 9360;
  return new Table({
    width: { size: W, type: WidthType.DXA },
    columnWidths: [W],
    rows: [
      new TableRow({
        children: [
          new TableCell({
            borders: borders("AAAAAA"),
            width: { size: W, type: WidthType.DXA },
            shading: { fill: "1E1E1E", type: ShadingType.CLEAR },
            margins: cellMarginsWide,
            children: text.split("\n").map(
              (line) =>
                new Paragraph({
                  spacing: { before: 20, after: 20 },
                  children: [
                    new TextRun({
                      text: line || " ",
                      font: "Courier New",
                      size: 18,
                      color: "D4D4D4",
                    }),
                  ],
                }),
            ),
          }),
        ],
      }),
    ],
  });
}

function twoCol(
  leftContent,
  rightContent,
  leftWidth = 4560,
  rightWidth = 4800,
) {
  return new Table({
    width: { size: 9360, type: WidthType.DXA },
    columnWidths: [leftWidth, rightWidth],
    rows: [
      new TableRow({
        children: [
          new TableCell({
            borders: noBorders(),
            width: { size: leftWidth, type: WidthType.DXA },
            margins: { top: 0, bottom: 0, left: 0, right: 160 },
            children: leftContent,
          }),
          new TableCell({
            borders: noBorders(),
            width: { size: rightWidth, type: WidthType.DXA },
            margins: { top: 0, bottom: 0, left: 160, right: 0 },
            children: rightContent,
          }),
        ],
      }),
    ],
  });
}

// ─── Step-box row builder ──────────────────────────────────────────────────
function stepRow(num, title, desc) {
  const numW = 700,
    titleW = 2500,
    descW = 6160;
  return new TableRow({
    children: [
      new TableCell({
        borders: borders(BLUE_MID),
        width: { size: numW, type: WidthType.DXA },
        shading: { fill: BLUE, type: ShadingType.CLEAR },
        margins: cellMargins,
        verticalAlign: "center",
        children: [
          new Paragraph({
            alignment: AlignmentType.CENTER,
            spacing: { before: 0, after: 0 },
            children: [
              new TextRun({
                text: num,
                bold: true,
                font: "Arial",
                size: 24,
                color: WHITE,
              }),
            ],
          }),
        ],
      }),
      new TableCell({
        borders: borders(BLUE_MID),
        width: { size: titleW, type: WidthType.DXA },
        shading: { fill: BLUE_LIGHT, type: ShadingType.CLEAR },
        margins: cellMargins,
        children: [
          new Paragraph({
            spacing: { before: 0, after: 0 },
            children: [
              new TextRun({
                text: title,
                bold: true,
                font: "Arial",
                size: 20,
                color: BLUE_DARK,
              }),
            ],
          }),
        ],
      }),
      new TableCell({
        borders: borders(BLUE_MID),
        width: { size: descW, type: WidthType.DXA },
        margins: cellMargins,
        children: [
          new Paragraph({
            spacing: { before: 0, after: 0 },
            children: [new TextRun({ text: desc, font: "Arial", size: 20 })],
          }),
        ],
      }),
    ],
  });
}

function stepsTable(rows) {
  const numW = 700,
    titleW = 2500,
    descW = 6160;
  return new Table({
    width: { size: 9360, type: WidthType.DXA },
    columnWidths: [numW, titleW, descW],
    rows: [
      new TableRow({
        children: [
          new TableCell({
            borders: borders(BLUE_DARK),
            width: { size: numW, type: WidthType.DXA },
            shading: { fill: BLUE_DARK, type: ShadingType.CLEAR },
            margins: cellMargins,
            children: [
              new Paragraph({
                spacing: { before: 0, after: 0 },
                children: [
                  new TextRun({
                    text: "#",
                    bold: true,
                    font: "Arial",
                    size: 20,
                    color: WHITE,
                  }),
                ],
              }),
            ],
          }),
          new TableCell({
            borders: borders(BLUE_DARK),
            width: { size: titleW, type: WidthType.DXA },
            shading: { fill: BLUE_DARK, type: ShadingType.CLEAR },
            margins: cellMargins,
            children: [
              new Paragraph({
                spacing: { before: 0, after: 0 },
                children: [
                  new TextRun({
                    text: "Step",
                    bold: true,
                    font: "Arial",
                    size: 20,
                    color: WHITE,
                  }),
                ],
              }),
            ],
          }),
          new TableCell({
            borders: borders(BLUE_DARK),
            width: { size: descW, type: WidthType.DXA },
            shading: { fill: BLUE_DARK, type: ShadingType.CLEAR },
            margins: cellMargins,
            children: [
              new Paragraph({
                spacing: { before: 0, after: 0 },
                children: [
                  new TextRun({
                    text: "Description",
                    bold: true,
                    font: "Arial",
                    size: 20,
                    color: WHITE,
                  }),
                ],
              }),
            ],
          }),
        ],
      }),
      ...rows.map(([n, t, d]) => stepRow(n, t, d)),
    ],
  });
}

function headerRow(cols, colWidths) {
  return new TableRow({
    children: cols.map(
      (c, i) =>
        new TableCell({
          borders: borders(BLUE_DARK),
          width: { size: colWidths[i], type: WidthType.DXA },
          shading: { fill: BLUE_DARK, type: ShadingType.CLEAR },
          margins: cellMargins,
          children: [
            new Paragraph({
              spacing: { before: 0, after: 0 },
              children: [
                new TextRun({
                  text: c,
                  bold: true,
                  font: "Arial",
                  size: 20,
                  color: WHITE,
                }),
              ],
            }),
          ],
        }),
    ),
  });
}

function dataRow(cols, colWidths, even = true) {
  return new TableRow({
    children: cols.map(
      (c, i) =>
        new TableCell({
          borders: borders(GREY_MED),
          width: { size: colWidths[i], type: WidthType.DXA },
          shading: { fill: even ? WHITE : GREY_LIGHT, type: ShadingType.CLEAR },
          margins: cellMargins,
          children: [
            new Paragraph({
              spacing: { before: 0, after: 0 },
              children: [
                typeof c === "string"
                  ? new TextRun({ text: c, font: "Arial", size: 20 })
                  : c,
              ],
            }),
          ],
        }),
    ),
  });
}

function dataTable(headers, rows, colWidths) {
  return new Table({
    width: { size: 9360, type: WidthType.DXA },
    columnWidths: colWidths,
    rows: [
      headerRow(headers, colWidths),
      ...rows.map((r, i) => dataRow(r, colWidths, i % 2 === 0)),
    ],
  });
}

// ─── Build document ────────────────────────────────────────────────────────
const doc = new Document({
  numbering: {
    config: [
      {
        reference: "bullets",
        levels: [
          {
            level: 0,
            format: LevelFormat.BULLET,
            text: "•",
            alignment: AlignmentType.LEFT,
            style: { paragraph: { indent: { left: 720, hanging: 360 } } },
          },
          {
            level: 1,
            format: LevelFormat.BULLET,
            text: "◦",
            alignment: AlignmentType.LEFT,
            style: { paragraph: { indent: { left: 1080, hanging: 360 } } },
          },
        ],
      },
      {
        reference: "numbers",
        levels: [
          {
            level: 0,
            format: LevelFormat.DECIMAL,
            text: "%1.",
            alignment: AlignmentType.LEFT,
            style: { paragraph: { indent: { left: 720, hanging: 360 } } },
          },
        ],
      },
    ],
  },
  styles: {
    default: { document: { run: { font: "Arial", size: 20, color: BLACK } } },
    paragraphStyles: [
      {
        id: "Heading1",
        name: "Heading 1",
        basedOn: "Normal",
        next: "Normal",
        quickFormat: true,
        run: { size: 32, bold: true, font: "Arial", color: WHITE },
        paragraph: { spacing: { before: 360, after: 160 }, outlineLevel: 0 },
      },
      {
        id: "Heading2",
        name: "Heading 2",
        basedOn: "Normal",
        next: "Normal",
        quickFormat: true,
        run: { size: 26, bold: true, font: "Arial", color: WHITE },
        paragraph: { spacing: { before: 320, after: 120 }, outlineLevel: 1 },
      },
      {
        id: "Heading3",
        name: "Heading 3",
        basedOn: "Normal",
        next: "Normal",
        quickFormat: true,
        run: { size: 24, bold: true, font: "Arial", color: BLUE },
        paragraph: { spacing: { before: 240, after: 100 }, outlineLevel: 2 },
      },
      {
        id: "Heading4",
        name: "Heading 4",
        basedOn: "Normal",
        next: "Normal",
        quickFormat: true,
        run: {
          size: 22,
          bold: true,
          italics: true,
          font: "Arial",
          color: BLUE_DARK,
        },
        paragraph: { spacing: { before: 180, after: 80 }, outlineLevel: 3 },
      },
    ],
  },
  sections: [
    {
      properties: {
        page: {
          size: { width: 12240, height: 15840 },
          margin: { top: 1080, right: 1080, bottom: 1080, left: 1080 },
        },
      },
      headers: {
        default: new Header({
          children: [
            new Table({
              width: { size: 10080, type: WidthType.DXA },
              columnWidths: [7200, 2880],
              rows: [
                new TableRow({
                  children: [
                    new TableCell({
                      borders: noBorders(),
                      width: { size: 7200, type: WidthType.DXA },
                      shading: { fill: BLUE_DARK, type: ShadingType.CLEAR },
                      margins: { top: 80, bottom: 80, left: 160, right: 0 },
                      children: [
                        new Paragraph({
                          spacing: { before: 0, after: 0 },
                          children: [
                            new TextRun({
                              text: "Auth System — Technical Documentation",
                              bold: true,
                              font: "Arial",
                              size: 18,
                              color: WHITE,
                            }),
                          ],
                        }),
                      ],
                    }),
                    new TableCell({
                      borders: noBorders(),
                      width: { size: 2880, type: WidthType.DXA },
                      shading: { fill: BLUE, type: ShadingType.CLEAR },
                      margins: { top: 80, bottom: 80, left: 0, right: 160 },
                      children: [
                        new Paragraph({
                          alignment: AlignmentType.RIGHT,
                          spacing: { before: 0, after: 0 },
                          children: [
                            new TextRun({
                              text: "Version 1.0 — 2026",
                              font: "Arial",
                              size: 18,
                              color: WHITE,
                            }),
                          ],
                        }),
                      ],
                    }),
                  ],
                }),
              ],
            }),
          ],
        }),
      },
      footers: {
        default: new Footer({
          children: [
            new Paragraph({
              spacing: { before: 80, after: 0 },
              border: {
                top: {
                  style: BorderStyle.SINGLE,
                  size: 2,
                  color: BLUE_MID,
                  space: 4,
                },
              },
              tabStops: [
                { type: TabStopType.RIGHT, position: TabStopPosition.MAX },
              ],
              children: [
                new TextRun({
                  text: "Confidential — Internal Use Only",
                  font: "Arial",
                  size: 16,
                  color: "888888",
                }),
                new TextRun({
                  text: "\tPage ",
                  font: "Arial",
                  size: 16,
                  color: "888888",
                }),
                new TextRun({
                  children: ["PAGE"],
                  font: "Arial",
                  size: 16,
                  color: "888888",
                }),
              ],
            }),
          ],
        }),
      },
      children: [
        // ═══════════════════════════════════════════════════════════════
        // COVER PAGE
        // ═══════════════════════════════════════════════════════════════
        spacer(4),
        new Paragraph({
          alignment: AlignmentType.CENTER,
          spacing: { before: 0, after: 0 },
          children: [
            new TextRun({
              text: "AUTH SYSTEM",
              bold: true,
              font: "Arial",
              size: 72,
              color: BLUE_DARK,
            }),
          ],
        }),
        new Paragraph({
          alignment: AlignmentType.CENTER,
          spacing: { before: 60, after: 0 },
          children: [
            new TextRun({
              text: "Technical Documentation",
              font: "Arial",
              size: 40,
              color: BLUE,
            }),
          ],
        }),
        spacer(1),
        new Table({
          width: { size: 5040, type: WidthType.DXA },
          columnWidths: [5040],
          rows: [
            new TableRow({
              children: [
                new TableCell({
                  borders: noBorders(),
                  width: { size: 5040, type: WidthType.DXA },
                  shading: { fill: BLUE, type: ShadingType.CLEAR },
                  margins: { top: 6, bottom: 6, left: 0, right: 0 },
                  children: [
                    new Paragraph({
                      spacing: { before: 0, after: 0 },
                      children: [new TextRun(" ")],
                    }),
                  ],
                }),
              ],
            }),
          ],
        }),
        spacer(1),
        new Paragraph({
          alignment: AlignmentType.CENTER,
          spacing: { before: 0, after: 60 },
          children: [
            new TextRun({
              text: "Multi-step user registration & authentication with",
              font: "Arial",
              size: 22,
              color: "444444",
            }),
          ],
        }),
        new Paragraph({
          alignment: AlignmentType.CENTER,
          spacing: { before: 0, after: 0 },
          children: [
            new TextRun({
              text: "Proof-of-Work  ·  Email Verification  ·  TOTP 2FA",
              font: "Arial",
              size: 22,
              color: BLUE,
              bold: true,
            }),
          ],
        }),
        spacer(4),
        new Table({
          width: { size: 6000, type: WidthType.DXA },
          columnWidths: [2400, 3600],
          rows: [
            new TableRow({
              children: [
                new TableCell({
                  borders: borders(BLUE_MID),
                  width: { size: 2400, type: WidthType.DXA },
                  shading: { fill: BLUE_LIGHT, type: ShadingType.CLEAR },
                  margins: cellMargins,
                  children: [
                    new Paragraph({
                      spacing: { before: 0, after: 0 },
                      children: [
                        new TextRun({
                          text: "Version",
                          bold: true,
                          font: "Arial",
                          size: 20,
                          color: BLUE_DARK,
                        }),
                      ],
                    }),
                  ],
                }),
                new TableCell({
                  borders: borders(BLUE_MID),
                  width: { size: 3600, type: WidthType.DXA },
                  margins: cellMargins,
                  children: [
                    new Paragraph({
                      spacing: { before: 0, after: 0 },
                      children: [
                        new TextRun({ text: "1.0", font: "Arial", size: 20 }),
                      ],
                    }),
                  ],
                }),
              ],
            }),
            new TableRow({
              children: [
                new TableCell({
                  borders: borders(BLUE_MID),
                  width: { size: 2400, type: WidthType.DXA },
                  shading: { fill: BLUE_LIGHT, type: ShadingType.CLEAR },
                  margins: cellMargins,
                  children: [
                    new Paragraph({
                      spacing: { before: 0, after: 0 },
                      children: [
                        new TextRun({
                          text: "Language",
                          bold: true,
                          font: "Arial",
                          size: 20,
                          color: BLUE_DARK,
                        }),
                      ],
                    }),
                  ],
                }),
                new TableCell({
                  borders: borders(BLUE_MID),
                  width: { size: 3600, type: WidthType.DXA },
                  margins: cellMargins,
                  children: [
                    new Paragraph({
                      spacing: { before: 0, after: 0 },
                      children: [
                        new TextRun({
                          text: "Python 3.12+",
                          font: "Arial",
                          size: 20,
                        }),
                      ],
                    }),
                  ],
                }),
              ],
            }),
            new TableRow({
              children: [
                new TableCell({
                  borders: borders(BLUE_MID),
                  width: { size: 2400, type: WidthType.DXA },
                  shading: { fill: BLUE_LIGHT, type: ShadingType.CLEAR },
                  margins: cellMargins,
                  children: [
                    new Paragraph({
                      spacing: { before: 0, after: 0 },
                      children: [
                        new TextRun({
                          text: "Classification",
                          bold: true,
                          font: "Arial",
                          size: 20,
                          color: BLUE_DARK,
                        }),
                      ],
                    }),
                  ],
                }),
                new TableCell({
                  borders: borders(BLUE_MID),
                  width: { size: 3600, type: WidthType.DXA },
                  margins: cellMargins,
                  children: [
                    new Paragraph({
                      spacing: { before: 0, after: 0 },
                      children: [
                        new TextRun({
                          text: "Confidential — Internal Use Only",
                          font: "Arial",
                          size: 20,
                        }),
                      ],
                    }),
                  ],
                }),
              ],
            }),
          ],
        }),
        pageBreak(),

        // ═══════════════════════════════════════════════════════════════
        // 1. OVERVIEW
        // ═══════════════════════════════════════════════════════════════
        h1("1. System Overview"),
        spacer(1),
        para(
          "The Auth System provides a complete, multi-step user registration and authentication pipeline built in Python. It protects against bots through Proof-of-Work challenges, verifies user identity through email codes, and enforces two-factor authentication via TOTP before account creation.",
        ),
        spacer(1),

        h3("Architecture"),
        para("The system is organised into two layers:"),
        spacer(1),
        twoCol(
          [
            paraRuns([
              new TextRun({
                text: "Modules",
                bold: true,
                font: "Arial",
                size: 20,
                color: BLUE_DARK,
              }),
            ]),
            para(
              "Independent, testable components, each responsible for a single concern:",
            ),
            bullet(
              "pow.py — Proof-of-Work challenge generation and verification",
            ),
            bullet("email.py — Email address validation and code verification"),
            bullet("totp.py — TOTP secret generation and token verification"),
            bullet(
              "user.py — User creation, password hashing, and user management",
            ),
            bullet(
              "storage.py — Thread-safe, file-backed user data persistence",
            ),
          ],
          [
            paraRuns([
              new TextRun({
                text: "Orchestrator",
                bold: true,
                font: "Arial",
                size: 20,
                color: BLUE_DARK,
              }),
            ]),
            para(
              "authFlow.py ties all modules together into a session-based state machine, exposing a clean API for registration, login, and password reset.",
            ),
            spacer(1),
            infoBox(
              "Design principle",
              "Each AuthFlow instance creates its own isolated module instances, so multiple instances can run side-by-side without shared state.",
              BLUE_LIGHT,
              BLUE_DARK,
            ),
          ],
        ),
        spacer(1),

        h3("Dependencies"),
        dataTable(
          ["Package", "Purpose", "Install"],
          [
            [
              "pyotp",
              "TOTP token generation and verification",
              "pip install pyotp",
            ],
            [
              "qrcode / pillow",
              "QR code SVG generation (optional)",
              "pip install qrcode pillow",
            ],
            ["freezegun", "Time-travel in tests", "pip install freezegun"],
            ["pytest", "Test runner", "pip install pytest"],
          ],
          [2200, 4360, 2800],
        ),
        spacer(1),
        pageBreak(),

        // ═══════════════════════════════════════════════════════════════
        // 2. REGISTRATION FLOW
        // ═══════════════════════════════════════════════════════════════
        h1("2. Registration Flow"),
        spacer(1),
        para(
          "Registration is a four-step state machine. Each step produces a session token that must be presented in subsequent requests. Steps cannot be skipped — the orchestrator enforces order strictly.",
        ),
        spacer(1),

        stepsTable([
          [
            "1",
            "Proof-of-Work",
            "Client receives a SHA-256 challenge and must find a nonce whose hash starts with N leading zeros. Prevents bot-automated registration.",
          ],
          [
            "2",
            "Email Verification",
            "Client submits an email address. The system sends a time-limited numeric code. Client must reply with the correct code within the expiry window.",
          ],
          [
            "3",
            "TOTP Setup",
            "After email verification, the server generates a TOTP secret. The client scans the QR code in an authenticator app and submits the first valid token to confirm setup.",
          ],
          [
            "4",
            "Account Creation",
            "Once all three verification steps are complete, the client submits a username and password. The account is created and the session is invalidated.",
          ],
        ]),
        spacer(1),

        h3("Session State Machine"),
        para(
          "Sessions are keyed by a 64-character hex token (32 bytes of entropy). Each session holds:",
        ),
        spacer(1),
        dataTable(
          ["Field", "Type", "Description"],
          [
            ["step", "str (AuthStep enum)", "Current position in the flow"],
            ["pow_verified", "bool", "PoW challenge has been solved"],
            ["email_verified", "bool", "Email code was accepted"],
            ["totp_verified", "bool", "TOTP token was confirmed"],
            ["email", "str | None", "Normalised (lowercase) email address"],
            [
              "totp_secret",
              "str | None",
              "Base-32 TOTP secret, stored temporarily in session",
            ],
            ["created_at", "datetime", "UTC timestamp of session creation"],
            ["last_activity", "datetime", "UTC timestamp of last interaction"],
          ],
          [2200, 2560, 4600],
        ),
        spacer(1),
        infoBox(
          "Session expiry",
          "Sessions expire after 30 minutes of inactivity by default (configurable via session_expiry_minutes). Expired sessions are cleaned up lazily on access and by a periodic cleanup call.",
          AMBER_BG,
          AMBER_TEXT,
        ),
        spacer(1),

        h3("Step 1 — Proof of Work"),
        para(
          "The client begins by calling init_pow(), which returns a challenge object:",
        ),
        spacer(1),
        codeBlock([
          "# 1. Request a challenge",
          "response = auth_flow.init_pow()",
          "# response.data = {",
          "#   'challenge_id': 'a3f9...',   # 32-char hex ID",
          "#   'challenge':    'Kx2b...',   # URL-safe random string",
          "#   'difficulty':   4,           # leading zeros required",
          "#   'timestamp':    1719000000.0",
          "# }",
          "",
          "# 2. Client finds nonce such that SHA-256(challenge + nonce).startswith('0' * difficulty)",
          "import hashlib",
          "nonce = 0",
          "prefix = '0' * response.data['difficulty']",
          "while True:",
          "    h = hashlib.sha256((response.data['challenge'] + str(nonce)).encode()).hexdigest()",
          "    if h.startswith(prefix): break",
          "    nonce += 1",
          "",
          "# 3. Submit solution",
          "result = auth_flow.verify_pow(response.data['challenge_id'], str(nonce))",
          "session_token = result.session_token  # store for subsequent calls",
        ]),
        spacer(1),
        infoBox(
          "Rate limiting",
          "generate_challenge() accepts an optional client_ip parameter. When provided, it enforces a configurable rate limit (default: 30 requests/minute per IP) to prevent abuse.",
          BLUE_LIGHT,
          BLUE_DARK,
        ),
        spacer(1),

        h3("Step 2 — Email Verification"),
        para(
          "With a valid session token from Step 1, the client submits an email address:",
        ),
        spacer(1),
        codeBlock([
          "# Submit email",
          "response = auth_flow.submit_email(session_token, 'user@example.com')",
          "# response.step = 'email_code_sent'",
          "# response.data = {",
          "#   'message':          'Verification code sent',",
          "#   'email':            'use***@example.com',  # masked",
          "#   'expires_in_seconds': 600,",
          "#   'expires_at':       '2026-01-01T00:10:00+00:00'",
          "# }",
          "",
          "# Submit the 6-digit code received by email",
          "result = auth_flow.verify_email_code(session_token, '483920')",
          "# result.step = 'email_verified'",
          "# result.data['totp']['qr_code_uri'] = 'otpauth://totp/...'",
          "# result.data['totp']['manual_key']  = 'BASE32SECRET'",
        ]),
        spacer(1),
        para(
          "The email module validates addresses before sending a code. The following are rejected:",
        ),
        bullet("Invalid format (no @ sign, empty local part)"),
        bullet(
          "Domains on the built-in disposable email blocklist (e.g. mailinator.com, guerrillamail.com)",
        ),
        bullet("Domains explicitly listed in a custom blocklist JSON file"),
        spacer(1),
        infoBox(
          "Security note",
          "Email verification codes are compared using hmac.compare_digest() to prevent timing attacks. After the configured max_attempts (default: 3), the code record is invalidated and the user must restart the session.",
          RED_BG,
          RED_TEXT,
        ),
        spacer(1),

        h3("Step 3 — TOTP Setup"),
        para(
          "After email verification, the server generates a fresh TOTP secret and returns both a provisioning URI (for QR code display on the frontend) and a manual entry key:",
        ),
        spacer(1),
        codeBlock([
          "# The TOTP data is returned inside verify_email_code()'s response:",
          "qr_uri     = result.data['totp']['qr_code_uri']  # otpauth://totp/...",
          "manual_key = result.data['totp']['manual_key']   # JBSWY3DPEHPK3PXP",
          "# NOTE: 'secret' is intentionally NOT exposed in the response.",
          "",
          "# Frontend displays QR code. User scans with Google Authenticator / Authy.",
          "# User then submits their first token:",
          "totp_response = auth_flow.verify_totp(session_token, '123456')",
          "# totp_response.step = 'totp_verified'",
          "# totp_response.data['ready_for_registration'] = True",
        ]),
        spacer(1),
        infoBox(
          "TOTP window",
          "Verification allows a configurable time window (default: ±1 period = ±30 seconds) to tolerate minor clock drift between server and client device.",
          BLUE_LIGHT,
          BLUE_DARK,
        ),
        spacer(1),

        h3("Step 4 — Account Creation"),
        spacer(1),
        codeBlock([
          "response = auth_flow.create_account_sync(",
          "    session_token,",
          "    username='alice',",
          "    password='SecurePass123!'",
          ")",
          "# response.step = 'account_created'",
          "# response.data = {",
          "#   'message':  'User created successfully',",
          "#   'user_id':  'a1b2c3d4...',",
          "#   'username': 'alice',",
          "#   'email':    'ali***@example.com'",
          "# }",
          "# Session is destroyed after successful creation.",
        ]),
        spacer(1),
        para("At this step the system also:"),
        bullet(
          "Validates the username (length, allowed characters, reserved names, uniqueness)",
        ),
        bullet(
          "Validates the password against complexity rules (≥3 of 5 criteria, see §5)",
        ),
        bullet(
          "Hashes the password with PBKDF2-SHA512 (600,000 iterations in production)",
        ),
        bullet(
          "Stores the TOTP secret in the user record and marks TOTP as enabled",
        ),
        bullet("Marks the email address as verified"),
        bullet("Destroys the registration session"),
        spacer(1),
        pageBreak(),

        // ═══════════════════════════════════════════════════════════════
        // 3. LOGIN FLOW
        // ═══════════════════════════════════════════════════════════════
        h1("3. Login Flow"),
        spacer(1),
        para(
          "Login is a single call that handles both password verification and optional TOTP in one round trip when the TOTP token is known upfront. The flow adapts based on whether the user has 2FA enabled.",
        ),
        spacer(1),

        h3("Basic Usage"),
        codeBlock([
          "# Attempt login — provide TOTP token if known",
          "response = auth_flow.login(",
          "    username='alice',",
          "    password='SecurePass123!',",
          "    totp_token='',   # empty string if unknown yet",
          ")",
          "",
          "if response.step == 'logged_in':",
          "    # Success — 2FA not enabled, or token was correct",
          "    session_token = response.session_token",
          "",
          "elif response.step == 'totp_required':",
          "    # User has 2FA — prompt for code then retry",
          "    totp_token = prompt_user()",
          "    response = auth_flow.login('alice', 'SecurePass123!', totp_token)",
          "",
          "elif response.step == 'error':",
          "    print(response.data['message'])  # 'Invalid username or password'",
        ]),
        spacer(1),

        h3("Login Response States"),
        dataTable(
          ["response.step", "Meaning", "next_action"],
          [
            [
              "logged_in",
              "Authentication succeeded. Session token is in response.session_token.",
              "—",
            ],
            [
              "totp_required",
              "Password accepted but TOTP token is required. Retry with token.",
              "continue",
            ],
            [
              "error",
              "Failure — see response.data['message'] for reason.",
              "retry or restart",
            ],
          ],
          [2400, 4560, 2400],
        ),
        spacer(1),
        infoBox(
          "Timing safety",
          "When a username is not found, verify_password() still runs a dummy PBKDF2 hash so that the response time is the same whether the user exists or not, preventing user enumeration via timing.",
          RED_BG,
          RED_TEXT,
        ),
        spacer(1),
        pageBreak(),

        // ═══════════════════════════════════════════════════════════════
        // 4. PASSWORD RESET FLOW
        // ═══════════════════════════════════════════════════════════════
        h1("4. Password Reset Flow"),
        spacer(1),

        stepsTable([
          [
            "1",
            "Initiate reset",
            "Client calls initiate_password_reset(email). A verification code is generated and sent. The response is identical whether or not the email is registered, preventing enumeration.",
          ],
          [
            "2",
            "Verify code & set new password",
            "Client calls complete_password_reset(email, code, new_password). Code is validated, new password is checked for complexity, then re-hashed and stored.",
          ],
        ]),
        spacer(1),
        codeBlock([
          "# Step 1 — request reset",
          "auth_flow.initiate_password_reset('alice@example.com')",
          "# Always returns step='reset_code_sent' regardless of email existence",
          "",
          "# Step 2 — complete reset",
          "response = auth_flow.complete_password_reset(",
          "    email='alice@example.com',",
          "    code='748291',",
          "    new_password='NewSecure!456'",
          ")",
          "# response.step = 'password_reset_complete'",
        ]),
        spacer(1),
        infoBox(
          "No TOTP challenge on reset",
          "The password reset flow uses only email verification as the second factor. If you require TOTP re-verification on reset, layer that check before calling complete_password_reset().",
          AMBER_BG,
          AMBER_TEXT,
        ),
        spacer(1),
        pageBreak(),

        // ═══════════════════════════════════════════════════════════════
        // 5. MODULE REFERENCE
        // ═══════════════════════════════════════════════════════════════
        h1("5. Module Reference"),
        spacer(1),

        // ── AuthFlow ────────────────────────────────────────────────────
        h2("5.1  AuthFlow  (orchestrator/authFlow.py)"),
        spacer(1),
        para(
          "The main entry point. Instantiate directly or use the get_auth_flow() singleton helper.",
        ),
        spacer(1),

        h4("Constructor"),
        dataTable(
          ["Parameter", "Type", "Default", "Description"],
          [
            [
              "session_expiry_minutes",
              "int",
              "30",
              "How long registration sessions remain valid",
            ],
            [
              "pow_difficulty",
              "int",
              "4",
              "SHA-256 leading zeros required for PoW",
            ],
            [
              "pow_expiry_seconds",
              "int",
              "300",
              "How long a PoW challenge stays valid (5 min)",
            ],
            [
              "email_code_length",
              "int",
              "6",
              "Length of numeric verification codes",
            ],
            [
              "email_expiry_seconds",
              "int",
              "600",
              "How long an email code stays valid (10 min)",
            ],
            [
              "email_max_attempts",
              "int",
              "3",
              "Wrong-code attempts before code is invalidated",
            ],
            [
              "totp_window",
              "int",
              "1",
              "Time-step tolerance for TOTP (±30 s per step)",
            ],
            [
              "blocklist_path",
              "str | None",
              "None",
              "Path to JSON file of blocked email domains",
            ],
          ],
          [2600, 1600, 1200, 3960],
        ),
        spacer(1),

        h4("Key Methods"),
        dataTable(
          ["Method", "Returns", "Description"],
          [
            [
              "init_pow()",
              "AuthResponse",
              "Generate a PoW challenge. No session required.",
            ],
            [
              "verify_pow(challenge_id, nonce)",
              "AuthResponse",
              "Verify solution; creates and returns session token on success.",
            ],
            [
              "submit_email(session_token, email)",
              "AuthResponse",
              "Validate email and send verification code.",
            ],
            [
              "verify_email_code(session_token, code)",
              "AuthResponse",
              "Verify code; returns TOTP QR URI on success.",
            ],
            [
              "verify_totp(session_token, token)",
              "AuthResponse",
              "Confirm TOTP setup; marks session ready for account creation.",
            ],
            [
              "create_account_sync(session_token, username, password)",
              "AuthResponse",
              "Create the account after all steps are complete.",
            ],
            [
              "login(username, password, totp_token)",
              "AuthResponse",
              "Full login: password + optional TOTP.",
            ],
            [
              "initiate_password_reset(email)",
              "AuthResponse",
              "Send reset code (always returns success to prevent enumeration).",
            ],
            [
              "complete_password_reset(email, code, new_password)",
              "AuthResponse",
              "Verify code and update password.",
            ],
            [
              "get_session_status(session_token)",
              "dict",
              "Returns session step and verification flags.",
            ],
            [
              "invalidate_session(session_token)",
              "bool",
              "Manually destroy a session.",
            ],
            [
              "cleanup_sessions()",
              "int",
              "Remove expired sessions; returns count removed.",
            ],
            [
              "get_status()",
              "dict",
              "System-wide status: active sessions, module stats.",
            ],
            [
              "reset()",
              "None",
              "Clear all sessions and module state (test use).",
            ],
          ],
          [3400, 1600, 4360],
        ),
        spacer(1),

        h4("AuthResponse"),
        para("All methods return an AuthResponse dataclass:"),
        codeBlock([
          "@dataclass",
          "class AuthResponse:",
          "    step:          str               # current state (AuthStep enum value)",
          "    data:          Dict[str, Any]    # step-specific payload",
          "    next_action:   Optional[str]     # hint for client (NextAction enum value)",
          "    session_token: Optional[str]     # set when a session is created",
        ]),
        spacer(1),
        dataTable(
          ["AuthStep value", "Meaning"],
          [
            ["pow_challenge", "PoW challenge issued"],
            ["pow_verified", "PoW solved; session created"],
            ["email_code_sent", "Verification code dispatched"],
            ["email_verified", "Email confirmed; TOTP QR returned"],
            ["totp_verified", "TOTP setup confirmed"],
            ["account_created", "User account created; session destroyed"],
            ["logged_in", "Login succeeded"],
            ["totp_required", "Password correct; TOTP token needed"],
            ["error", "Something went wrong; see data['message']"],
          ],
          [3000, 6360],
        ),
        spacer(1),
        pageBreak(),

        // ── PoW ─────────────────────────────────────────────────────────
        h2("5.2  PoW  (modules/pow.py)"),
        spacer(1),
        para(
          "Proof-of-Work implementation using SHA-256. Challenges are stored in memory with a background cleanup thread that removes expired entries.",
        ),
        spacer(1),
        h4("Constructor parameters"),
        dataTable(
          ["Parameter", "Default", "Description"],
          [
            [
              "difficulty",
              "4",
              "Number of leading '0' hex characters required in hash output",
            ],
            [
              "expiry_seconds",
              "300",
              "Seconds before an unsolved challenge is discarded",
            ],
            [
              "cleanup_interval",
              "60",
              "How often (seconds) the background thread purges expired challenges",
            ],
            [
              "rate_limit_per_minute",
              "30",
              "Max challenges issued per IP per minute (0 = disabled)",
            ],
          ],
          [2800, 1200, 5360],
        ),
        spacer(1),
        h4("Key methods"),
        bulletRuns([
          new TextRun({
            text: "generate_challenge(client_ip=None) → Challenge",
            bold: true,
            font: "Arial",
            size: 20,
          }),
          new TextRun({
            text: " — returns a Challenge with challenge_id, challenge string, difficulty, and timestamp. Returns None if the IP is rate-limited.",
            font: "Arial",
            size: 20,
          }),
        ]),
        bulletRuns([
          new TextRun({
            text: "verify(challenge_id, nonce) → VerificationResult",
            bold: true,
            font: "Arial",
            size: 20,
          }),
          new TextRun({
            text: " — checks the hash, marks the challenge used, and returns a success/failure result. Challenges can only be used once.",
            font: "Arial",
            size: 20,
          }),
        ]),
        bulletRuns([
          new TextRun({
            text: "solve_challenge(challenge, difficulty) → str",
            bold: true,
            font: "Arial",
            size: 20,
          }),
          new TextRun({
            text: " — utility method that brute-forces a valid nonce (useful for testing and CLI tooling).",
            font: "Arial",
            size: 20,
          }),
        ]),
        spacer(1),
        infoBox(
          "Difficulty guide",
          "Difficulty 2 = ~128 hashes avg (instant). Difficulty 3 = ~2,048 hashes (~20 ms). Difficulty 4 = ~32,768 hashes (~300 ms). Difficulty 5 = ~524,288 hashes (~5 s). Recommended: 3-4 for web clients.",
          BLUE_LIGHT,
          BLUE_DARK,
        ),
        spacer(1),

        // ── Email ────────────────────────────────────────────────────────
        h2("5.3  EmailVerifier  (modules/email.py)"),
        spacer(1),
        para(
          "Handles email address validation and numeric verification code lifecycle. Uses hmac.compare_digest() for timing-safe code comparison.",
        ),
        spacer(1),
        h4("Constructor parameters"),
        dataTable(
          ["Parameter", "Default", "Description"],
          [
            ["code_length", "6", "Digits in the generated code"],
            [
              "expiry_seconds",
              "600",
              "Seconds before code expires (10 minutes)",
            ],
            ["max_attempts", "3", "Wrong attempts before code is invalidated"],
            [
              "blocklist_path",
              "None",
              "Path to JSON file listing blocked domains",
            ],
          ],
          [2400, 1200, 5760],
        ),
        spacer(1),
        h4("Email validation"),
        para(
          "validate_email() classifies addresses with the EmailStatus enum:",
        ),
        dataTable(
          ["Status", "Meaning"],
          [
            ["VALID", "Address passes all checks"],
            [
              "INVALID_FORMAT",
              "No @ sign, empty local part, or other format error",
            ],
            [
              "DISPOSABLE",
              "Domain is on the built-in disposable/temporary email blocklist",
            ],
            ["BLOCKED_DOMAIN", "Domain is in the custom blocklist file"],
            ["SPAM", "Domain matched an additional spam heuristic"],
          ],
          [2400, 6960],
        ),
        spacer(1),

        // ── TOTP ─────────────────────────────────────────────────────────
        h2("5.4  TOTPManager  (modules/totp.py)"),
        spacer(1),
        para(
          "Wraps pyotp to manage TOTP secrets keyed by email address. Secrets are held in memory; they are written to the user record in storage by the orchestrator after TOTP is confirmed.",
        ),
        spacer(1),
        h4("Constructor parameters"),
        dataTable(
          ["Parameter", "Default", "Description"],
          [
            [
              "issuer",
              '"AuthSystem"',
              "Organisation name shown in the authenticator app",
            ],
            [
              "window",
              "1",
              "Time-step tolerance: 1 means the token from ±1 period (±30 s) is also accepted",
            ],
          ],
          [2400, 2400, 4560],
        ),
        spacer(1),
        h4("Key methods"),
        bulletRuns([
          new TextRun({
            text: "generate_secret(email) → TOTPSetupResult",
            bold: true,
            font: "Arial",
            size: 20,
          }),
          new TextRun({
            text: " — generates a 160-bit base-32 secret, stores it keyed by lowercase email, and returns the secret, a provisioning URI, and a manual entry key.",
            font: "Arial",
            size: 20,
          }),
        ]),
        bulletRuns([
          new TextRun({
            text: "verify_token(email, token) → dict",
            bold: true,
            font: "Arial",
            size: 20,
          }),
          new TextRun({
            text: " — looks up the secret by email and calls pyotp.TOTP.verify() with the configured window.",
            font: "Arial",
            size: 20,
          }),
        ]),
        bulletRuns([
          new TextRun({
            text: "get_current_token(email) → str | None",
            bold: true,
            font: "Arial",
            size: 20,
          }),
          new TextRun({
            text: " — returns the current valid 6-digit token for an email. Used in tests.",
            font: "Arial",
            size: 20,
          }),
        ]),
        spacer(1),

        // ── UserManager ──────────────────────────────────────────────────
        h2("5.5  UserManager  (modules/user.py)"),
        spacer(1),
        para(
          "Manages user lifecycle: creation, retrieval, password management, and TOTP enablement.",
        ),
        spacer(1),
        h4("Password hashing"),
        para("Passwords are hashed with PBKDF2-HMAC-SHA512:"),
        bullet(
          "600,000 iterations in production (OWASP 2023 recommendation for SHA-512)",
        ),
        bullet(
          "1,000 iterations in test environments (detected via pbkdf2_iterations constructor param)",
        ),
        bullet("16-byte cryptographically random salt generated per password"),
        bullet("64-byte derived key"),
        bullet(
          "Comparison via hmac.compare_digest() to prevent timing attacks",
        ),
        spacer(1),
        h4("Password complexity rules"),
        para(
          "A password is valid if it meets at least 3 of the following 5 criteria AND is at least 8 characters:",
        ),
        numbered("Contains an uppercase letter (A–Z)"),
        numbered("Contains a lowercase letter (a–z)"),
        numbered("Contains a digit (0–9)"),
        numbered("Contains a special character (!@#$%^&* etc.)"),
        numbered("Is 12 or more characters (length bonus)"),
        spacer(1),
        para(
          "Additionally, passwords matching a common-password list or containing keyboard patterns (qwerty, 123456, etc.) are rejected regardless of complexity score.",
        ),
        spacer(1),
        h4("Username rules"),
        bullet("3–30 characters"),
        bullet("Letters, numbers, and underscores only"),
        bullet(
          "Cannot match reserved names: admin, root, system, support, test, etc.",
        ),
        bullet(
          "Cannot contain 5+ consecutive digits, 5+ repeated characters, or long letter+digit patterns",
        ),
        spacer(1),
        pageBreak(),

        // ── Storage ──────────────────────────────────────────────────────
        h2("5.6  Storage  (modules/storage.py)"),
        spacer(1),
        para(
          "File-backed, thread-safe key-value store for user records. Data is persisted as a JSON file. Both synchronous and async methods are provided.",
        ),
        spacer(1),
        h4("Constructor parameters"),
        dataTable(
          ["Parameter", "Default", "Description"],
          [
            ["data_dir", "cwd/auth/data", "Directory for the users.json file"],
            ["auto_save", "True", "Write to disk after every mutation"],
            ["pretty_print", "True", "Indent JSON for readability"],
          ],
          [2400, 2400, 4560],
        ),
        spacer(1),
        h4("Key methods"),
        dataTable(
          ["Method", "Sync/Async", "Description"],
          [
            [
              "save_user_sync(user)",
              "Sync",
              "Insert new user; returns False if username or email already exists",
            ],
            [
              "get_user_by_username(username)",
              "Sync",
              "Case-insensitive username lookup",
            ],
            [
              "get_user_by_email(email)",
              "Sync",
              "Email lookup via internal email→username map",
            ],
            [
              "update_user_sync(username, updates)",
              "Sync",
              "Merge updates dict into existing user record",
            ],
            [
              "delete_user_sync(username)",
              "Sync",
              "Remove user and clean up email map",
            ],
            ["username_exists(username)", "Sync", "Quick existence check"],
            ["email_exists(email)", "Sync", "Quick email uniqueness check"],
            [
              "get_all_users()",
              "Sync",
              "Return list of all user dicts (without sensitive fields by default)",
            ],
            ["clear_all()", "Sync", "Wipe all users and email map (test use)"],
          ],
          [3400, 1400, 4560],
        ),
        spacer(1),
        pageBreak(),

        // ═══════════════════════════════════════════════════════════════
        // 6. ERROR HANDLING
        // ═══════════════════════════════════════════════════════════════
        h1("6. Error Handling"),
        spacer(1),
        para(
          "All error responses share a common shape. The next_action field tells the client how to proceed:",
        ),
        spacer(1),
        codeBlock([
          "{",
          "  'step':        'error',",
          "  'data':        { 'message': 'Human-readable explanation' },",
          "  'next_action': 'restart'  # or 'retry', 'retry_code', 'retry_totp'",
          "}",
        ]),
        spacer(1),
        dataTable(
          ["next_action", "Client should…"],
          [
            ["restart", "Discard session and begin again from Step 1 (PoW)"],
            [
              "retry",
              "Fix the input (e.g. different email/username) and re-submit the same step",
            ],
            [
              "retry_code",
              "The email code was wrong but attempts remain — prompt user to try again",
            ],
            [
              "retry_totp",
              "The TOTP token was wrong — prompt user to enter the next code",
            ],
          ],
          [2400, 6960],
        ),
        spacer(1),

        h3("Common Error Scenarios"),
        dataTable(
          ["Scenario", "step", "next_action", "Cause"],
          [
            [
              "Invalid/expired session",
              "error",
              "restart",
              "Session not found or past expiry",
            ],
            [
              "PoW step skipped",
              "error",
              "restart",
              "Attempting email/TOTP before completing PoW",
            ],
            ["Disposable email", "error", "retry", "Domain on blocklist"],
            [
              "Wrong email code",
              "error",
              "retry_code",
              "Code mismatch with attempts remaining",
            ],
            [
              "Max email attempts",
              "error",
              "restart",
              "3 wrong codes — code invalidated",
            ],
            ["Wrong TOTP token", "error", "retry_totp", "Token mismatch"],
            ["Username taken", "error", "retry", "Username already in storage"],
            [
              "Weak password",
              "error",
              "retry",
              "Fewer than 3 complexity criteria met",
            ],
            [
              "Wrong password (login)",
              "error",
              "retry",
              "PBKDF2 hash mismatch",
            ],
          ],
          [2800, 1600, 1800, 3160],
        ),
        spacer(1),
        pageBreak(),

        // ═══════════════════════════════════════════════════════════════
        // 7. CONFIGURATION REFERENCE
        // ═══════════════════════════════════════════════════════════════
        h1("7. Configuration Reference"),
        spacer(1),
        para(
          "All parameters are set at instantiation time. For production usage:",
        ),
        spacer(1),
        codeBlock([
          "from orchestrator.authFlow import AuthFlow",
          "",
          "auth = AuthFlow(",
          "    session_expiry_minutes  = 30,",
          "    pow_difficulty          = 4,      # ~300 ms on average JS client",
          "    pow_expiry_seconds      = 300,    # 5 minutes to solve",
          "    email_code_length       = 6,",
          "    email_expiry_seconds    = 600,    # 10 minutes to enter code",
          "    email_max_attempts      = 3,",
          "    totp_window             = 1,      # ±30 seconds clock tolerance",
          "    blocklist_path          = '/etc/auth/blocked_domains.json'",
          ")",
        ]),
        spacer(1),
        h3("Blocked Domains JSON Format"),
        codeBlock([
          "{",
          '  "blocked_domains": [',
          '    "mailinator.com",',
          '    "guerrillamail.com",',
          '    "tempmail.org"',
          "  ]",
          "}",
        ]),
        spacer(1),
        pageBreak(),

        // ═══════════════════════════════════════════════════════════════
        // 8. TESTING
        // ═══════════════════════════════════════════════════════════════
        h1("8. Testing"),
        spacer(1),
        para(
          "The test suite (tests/test_auth_flow.py) contains 51 tests organised into 8 classes and uses pytest with freezegun for time-based scenarios.",
        ),
        spacer(1),

        h3("Running the Tests"),
        codeBlock([
          "# Install test dependencies",
          "pip install pytest pyotp freezegun qrcode pillow",
          "",
          "# Run all tests",
          "cd auth/",
          "python -m pytest tests/test_auth_flow.py -v",
          "",
          "# Run with coverage",
          "python -m pytest tests/test_auth_flow.py --cov=orchestrator --cov=modules -v",
        ]),
        spacer(1),

        h3("Test Classes"),
        dataTable(
          ["Class", "Tests", "Coverage area"],
          [
            [
              "TestAuthFlowInitialization",
              "3",
              "Constructor params, singleton pattern",
            ],
            [
              "TestSessionManagement",
              "9",
              "Session creation, expiry, cleanup, masking",
            ],
            [
              "TestProofOfWorkFlow",
              "5",
              "Challenge generation and verification edge cases",
            ],
            [
              "TestEmailVerificationFlow",
              "8",
              "Email submission, code verification, attempt limits",
            ],
            ["TestTOTPVerificationFlow", "4", "TOTP setup and verification"],
            [
              "TestAccountCreation",
              "5",
              "Full registration, duplicate detection, weak passwords",
            ],
            ["TestLoginFlow", "5", "Login, TOTP gating, invalid credentials"],
            [
              "TestPasswordReset",
              "5",
              "Reset initiation, code verification, new password validation",
            ],
            [
              "TestFullRegistrationFlow",
              "2",
              "End-to-end integration: complete registration → login",
            ],
            ["TestErrorHandling", "4", "Status reporting, reset, destroy"],
          ],
          [3200, 800, 5360],
        ),
        spacer(1),

        h3("Test Isolation"),
        para(
          "Each test receives a fresh AuthFlow instance via the auth_flow pytest fixture. Because AuthFlow now creates its own Storage backed by a temporary directory (auto_save=False), tests cannot share or corrupt each other's user data. The fixture calls flow.reset() on teardown.",
        ),
        spacer(1),
        infoBox(
          "PoW in tests",
          "The auth_flow fixture sets pow_difficulty=2 (instead of production default 4) to keep test execution fast. The test helper solve_pow_challenge() has a 1,000,000 nonce search limit to guarantee it always finds a solution at this difficulty.",
          GREEN_BG,
          GREEN,
        ),
        spacer(1),
        infoBox(
          "Retrieving email codes in tests",
          "In tests, call auth_flow.email_verifier.get_code_for_testing(email) to read back the code without needing a real mail server. This method is intentionally unrestricted — do not expose it through any API endpoint.",
          RED_BG,
          RED_TEXT,
        ),
        spacer(1),
        pageBreak(),

        // ═══════════════════════════════════════════════════════════════
        // 9. SECURITY NOTES
        // ═══════════════════════════════════════════════════════════════
        h1("9. Security Notes"),
        spacer(1),
        h3("What is protected"),
        bullet("Bot registration via Proof-of-Work"),
        bullet(
          "User enumeration via timing (dummy hash on unknown usernames; identical reset response for unknown emails)",
        ),
        bullet("Brute-force email codes via attempt limits and expiry"),
        bullet(
          "Password cracking via PBKDF2-SHA512 with 600,000 iterations and random salt",
        ),
        bullet(
          "TOTP secret leakage — secret is stored server-side only; the API response never exposes it",
        ),
        bullet(
          "Cross-session data leakage — each AuthFlow instance has an isolated Storage",
        ),
        spacer(1),

        h3("What is NOT provided out of the box"),
        bullet("Transport encryption — deploy behind HTTPS"),
        bullet(
          "TOTP replay attack prevention — add a used-token cache if required",
        ),
        bullet(
          "Account lockout on repeated failed logins — add a failed-attempt counter in Storage",
        ),
        bullet("Audit logging — add structured logging around key events"),
        bullet(
          "TOTP secret persistence across server restarts — secrets live in TOTPManager memory; store them in the user record immediately after generate_secret() if you need restartability",
        ),
        spacer(1),
        infoBox(
          "Production checklist",
          "✓ Set pow_difficulty ≥ 4  ✓ Serve over HTTPS  ✓ Rotate secrets  ✓ Configure a real email sender  ✓ Set a custom blocklist_path  ✓ Monitor cleanup_sessions() for memory growth",
          GREEN_BG,
          GREEN,
        ),
        spacer(1),
      ],
    },
  ],
});

Packer.toBuffer(doc).then((buf) => {
  fs.writeFileSync("./auth_documentation.docx", buf);
  console.log("Done");
});
