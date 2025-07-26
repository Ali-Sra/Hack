import sqlite3
import pandas as pd
from fpdf import FPDF

DB_FILE = "scan_results.db"

def generate_pdf_report():
    """ ایجاد گزارش در فرمت PDF از دیتابیس """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scan_results ORDER BY timestamp DESC")
    reports = cursor.fetchall()
    conn.close()

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.cell(200, 10, "Security Scan Report", ln=True, align="C")

    pdf.set_font("Arial", size=12)
    for report in reports:
        pdf.cell(200, 10, f"Target: {report[1]}", ln=True)
        pdf.multi_cell(200, 10, f"Report: {report[2]}")
        pdf.cell(200, 10, f"Date: {report[3]}", ln=True)
        pdf.ln(10)

    pdf.output("scan_report.pdf")

def generate_excel_report():
    """ ایجاد گزارش در فرمت Excel از دیتابیس """
    conn = sqlite3.connect(DB_FILE)
    df = pd.read_sql_query("SELECT * FROM scan_results ORDER BY timestamp DESC", conn)
    conn.close()
    df.to_excel("scan_report.xlsx", index=False)
