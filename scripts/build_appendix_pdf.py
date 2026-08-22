#!/usr/bin/env python3
"""Build the self-contained USENIX artifact appendix PDF."""

from __future__ import annotations

from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "artifact" / "ARTIFACT_APPENDIX.pdf"


def page_footer(canvas, document):
    canvas.saveState()
    canvas.setStrokeColor(colors.HexColor("#CBD5E1"))
    canvas.line(0.58 * inch, 0.45 * inch, 7.92 * inch, 0.45 * inch)
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#475569"))
    canvas.drawString(0.58 * inch, 0.28 * inch, "S-BFP Artifact Appendix")
    canvas.drawRightString(7.92 * inch, 0.28 * inch, f"Page {document.page}")
    canvas.restoreState()


def main() -> None:
    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(
            name="ArtifactTitle",
            parent=styles["Title"],
            fontName="Helvetica-Bold",
            fontSize=20,
            leading=23,
            alignment=TA_CENTER,
            textColor=colors.HexColor("#0F172A"),
            spaceAfter=8,
        )
    )
    styles.add(
        ParagraphStyle(
            name="ArtifactSubtitle",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=10,
            leading=14,
            alignment=TA_CENTER,
            textColor=colors.HexColor("#475569"),
            spaceAfter=14,
        )
    )
    styles.add(
        ParagraphStyle(
            name="ArtifactHeading",
            parent=styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=13,
            leading=16,
            textColor=colors.HexColor("#0F4C81"),
            spaceBefore=8,
            spaceAfter=5,
        )
    )
    styles.add(
        ParagraphStyle(
            name="ArtifactBody",
            parent=styles["BodyText"],
            fontName="Helvetica",
            fontSize=9.2,
            leading=12.2,
            textColor=colors.HexColor("#1E293B"),
            spaceAfter=5,
        )
    )
    styles.add(
        ParagraphStyle(
            name="ArtifactCode",
            parent=styles["Code"],
            fontName="Courier",
            fontSize=8.2,
            leading=11,
            leftIndent=8,
            rightIndent=8,
            borderColor=colors.HexColor("#CBD5E1"),
            borderWidth=0.5,
            borderPadding=6,
            backColor=colors.HexColor("#F8FAFC"),
            spaceBefore=3,
            spaceAfter=7,
        )
    )

    body = styles["ArtifactBody"]
    heading = styles["ArtifactHeading"]
    code = styles["ArtifactCode"]
    story = [
        Paragraph("S-BFP Artifact Appendix", styles["ArtifactTitle"]),
        Paragraph(
            "From Frozen Pose to Live Dance: Stochastic Browser Fingerprinting for Robust Risk-Based Authentication",
            styles["ArtifactSubtitle"],
        ),
        Paragraph("Artifact overview", heading),
        Paragraph(
            "S-BFP is a Flask and browser research prototype that turns a static browser fingerprint into a server-controlled challenge-response measurement. A deterministic random bit generator derives device-specific primitives, while a session input changes their spatial arrangement. The artifact implements Canvas text, Web Audio waveforms, and WebGL triangles.",
            body,
        ),
        Paragraph(
            "The package supports (1) functional inspection of all three browser workflows and (2) independent recomputation of the paper's stability and environment tables from a de-identified 213-participant summary dataset.",
            body,
        ),
        Paragraph("Claims and evaluation mapping", heading),
    ]

    table_data = [
        ["Paper claim", "Evaluation action", "Expected result"],
        ["Audio stability", "Run reproduction script", "206/206 (100.0%)"],
        ["Canvas stability", "Run reproduction script", "196/198 (99.0%)"],
        ["WebGL stability", "Run reproduction script", "177/193 (91.7%)"],
        ["Cohort distribution", "Inspect generated Table 3 CSV", "213 devices; exact row match"],
        ["Executable workflow", "Run all three browser panels", "Repeated render and stability summary"],
    ]
    table = Table(table_data, colWidths=[1.55 * inch, 2.8 * inch, 2.65 * inch], repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0F4C81")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 8.2),
                ("LEADING", (0, 0), (-1, -1), 10.5),
                ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#94A3B8")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F1F5F9")]),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    story.extend(
        [
            table,
            Spacer(1, 6),
            Paragraph("Scope", heading),
            Paragraph(
                "The artifact does not implement a complete production risk engine and does not claim to prove security against every adaptive attacker. WebGL instability is an evaluated result, not necessarily an execution failure. The restricted per-participant source collection is not part of the release package.",
                body,
            ),
            PageBreak(),
            Paragraph("Requirements and installation", heading),
            Paragraph(
                "Hardware: any x86-64 or ARM64 CPU, 1 GiB free memory, and about 300 MiB disk for native use. A discrete GPU is not required. Software: Python 3.11-3.13 and a current browser with Canvas, Web Audio, and WebGL. Docker with Compose v2 is optional.",
                body,
            ),
            Paragraph("Windows PowerShell", heading),
            Paragraph(r".\scripts\setup.ps1<br/>.\scripts\run.ps1", code),
            Paragraph("Linux or macOS", heading),
            Paragraph("sh scripts/setup.sh<br/>sh scripts/run.sh", code),
            Paragraph("Docker alternative", heading),
            Paragraph("docker compose up --build", code),
            Paragraph(
                "Open http://127.0.0.1:5001/. Native startup normally opens this address automatically. The aggregate reproduction is CPU-only and typically finishes in under one minute. Interactive rendering usually takes several seconds per modality.",
                body,
            ),
            Paragraph("Functional evaluation", heading),
            Paragraph(
                "1. Select Register and enter a pseudonymous username of 3-20 letters, digits, or underscores.<br/>2. Read and affirm the consent notice, then save the generated password.<br/>3. Acquire the exclusive test session.<br/>4. Run Canvas, Audio, and WebGL. Canvas performs five repetitions; Audio and WebGL perform ten.<br/>5. Confirm that every panel presents a completion message. A changed hash is a legitimate instability result.<br/>6. With default settings, the new runtime record must not contain an IP address, full user-agent string, or raw Canvas fingerprint.",
                body,
            ),
            Paragraph("Paper-table reproduction", heading),
            Paragraph("python scripts/reproduce_tables.py --verify-paper", code),
            PageBreak(),
            Paragraph("Expected reproduction result", heading),
            Paragraph(
                "Expected values: Audio 206/206; Canvas 196/198; WebGL 177/193; environment total 213.",
                body,
            ),
            Paragraph("Automated and package checks", heading),
            Paragraph(
                "python -m unittest discover -s tests -v<br/>python scripts/build_artifact.py<br/>python scripts/verify_artifact.py dist/s-bfp-usenix-artifact.zip",
                code,
            ),
            Paragraph(
                "The tests use an isolated temporary data directory. The package verifier requires the documentation and public dataset, verifies SHA-256 entries, checks the 213-row schema, and rejects restricted source, runtime-data, upload, cache, and Git paths.",
                body,
            ),
            Paragraph("Released data", heading),
            Paragraph(
                "data/public/records.jsonl is a deterministic aggregate of each participant's first collection session, matching the paper's cohort snapshot. Each row contains only a new sequential ID, coarse operating-system and browser categories, and modality availability, run count, unique-result count, and stability boolean.",
                body,
            ),
            Paragraph(
                "Original usernames, password material, IP addresses, full user agents, timestamps, renderer strings, seeds, rendering hashes, raw images, and audio samples are omitted. Evaluators do not need the restricted source records.",
                body,
            ),
            Paragraph("Limitations and troubleshooting", heading),
            Paragraph(
                "WebGL depends on the evaluator's browser and graphics stack. If unavailable, enable browser acceleration or use a current Chromium/Firefox build; aggregate reproduction does not require WebGL. If port 5001 is occupied, set S_BFP_PORT. Docker reproduces the server environment, not the host browser renderer. The process-local session coordinator supports one active evaluator and is not a multi-worker production design.",
                body,
            ),
            Paragraph("Submission notes", heading),
            Paragraph(
                "For an Available badge, deposit the exact sanitized release on a permanent platform and replace repository placeholders with the immutable version DOI. Before public release, authors must select explicit code/data licenses, add camera-ready citation metadata, reconcile the ethics statement with retained source fields, and verify a fresh extraction on the target platforms.",
                body,
            ),
        ]
    )

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    document = SimpleDocTemplate(
        str(OUTPUT),
        pagesize=letter,
        rightMargin=0.58 * inch,
        leftMargin=0.58 * inch,
        topMargin=0.48 * inch,
        bottomMargin=0.58 * inch,
        title="S-BFP Artifact Appendix",
        author="Anonymous artifact authors",
        subject="USENIX Security artifact evaluation roadmap",
    )
    document.build(story, onFirstPage=page_footer, onLaterPages=page_footer)
    print(f"Wrote {OUTPUT}")


if __name__ == "__main__":
    main()
