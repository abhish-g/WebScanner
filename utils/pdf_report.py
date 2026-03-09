from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from datetime import datetime
import os

def generate_pdf_report(url, result):
    os.makedirs("reports", exist_ok=True)

    filename = f"reports/scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    c = canvas.Canvas(filename, pagesize=A4)

    text = c.beginText(40, 800)
    text.setFont("Helvetica", 11)

    text.textLine("RAG Security Scanner – Security Report")
    text.textLine("")
    text.textLine(f"Target URL: {url}")
    text.textLine(f"Scan Time: {datetime.now()}")
    text.textLine("")
    text.textLine("Detected Issues:")

    if result["issues"]:
        for i in result["issues"]:
            text.textLine(
                f"- {i['attack']} | Confidence: {round(i['confidence']*100)}%"
            )
    else:
        text.textLine("- No vulnerabilities detected")

    text.textLine("")
    text.textLine("AI Explanation:")
    for line in result["explanation"].split("\n"):
        text.textLine(line)

    c.drawText(text)
    c.save()

    return filename
