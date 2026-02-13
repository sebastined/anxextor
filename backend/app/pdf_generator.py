"""
PDF Report Generation with reportlab and matplotlib
Generates professional security assessment reports with charts and CVE details
"""

import io
import requests
from datetime import datetime
from typing import Dict, List, Optional, Any
import matplotlib.pyplot as plt
import matplotlib
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak, Image
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY

# Use non-interactive backend for matplotlib
matplotlib.use('Agg')

class CVEFetcher:
    """Fetch CVE details from NVD API"""
    NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    def __init__(self, timeout: int = 5):
        self.timeout = timeout
        self.cache = {}
    
    def get_cve_details(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Fetch CVE details from NVD API"""
        if cve_id in self.cache:
            return self.cache[cve_id]
        
        try:
            params = {
                "keywordSearch": cve_id,
                "resultsPerPage": 1
            }
            response = requests.get(
                self.NVD_BASE_URL,
                params=params,
                timeout=self.timeout
            )
            response.raise_for_status()
            
            data = response.json()
            if data.get("vulnerabilities"):
                vuln = data["vulnerabilities"][0]["cve"]
                details = {
                    "id": vuln.get("id"),
                    "published": vuln.get("published"),
                    "lastModified": vuln.get("lastModified"),
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    "description": vuln.get("descriptions", [{}])[0].get("value", "N/A"),
                }
                self.cache[cve_id] = details
                return details
        except Exception as e:
            print(f"Error fetching CVE {cve_id}: {e}")
        
        return None


class ChartGenerator:
    """Generate matplotlib charts for PDF"""
    
    @staticmethod
    def create_severity_chart(findings: List[Dict]) -> io.BytesIO:
        """Create severity distribution pie chart"""
        severity_counts = {
            "Critical": len([f for f in findings if f.get("severity") == "Critical"]),
            "High": len([f for f in findings if f.get("severity") == "High"]),
            "Medium": len([f for f in findings if f.get("severity") == "Medium"]),
            "Low": len([f for f in findings if f.get("severity") == "Low"]),
        }
        
        colors_map = {
            "Critical": "#d32f2f",
            "High": "#f57c00",
            "Medium": "#fbc02d",
            "Low": "#388e3c",
        }
        
        fig, ax = plt.subplots(figsize=(6, 4))
        labels = [k for k, v in severity_counts.items() if v > 0]
        sizes = [v for v in severity_counts.values() if v > 0]
        colors_list = [colors_map[k] for k, v in severity_counts.items() if v > 0]
        
        ax.pie(sizes, labels=labels, colors=colors_list, autopct='%1.1f%%', startangle=90)
        ax.set_title("Severity Distribution", fontsize=12, fontweight='bold')
        
        img_buffer = io.BytesIO()
        plt.savefig(img_buffer, format='png', dpi=100, bbox_inches='tight')
        img_buffer.seek(0)
        plt.close(fig)
        
        return img_buffer
    
    @staticmethod
    def create_cve_chart(findings: List[Dict]) -> io.BytesIO:
        """Create CVE distribution bar chart"""
        with_cve = len([f for f in findings if f.get("cve")])
        without_cve = len(findings) - with_cve
        
        fig, ax = plt.subplots(figsize=(6, 4))
        categories = ["With CVE", "Without CVE"]
        counts = [with_cve, without_cve]
        colors_list = ["#1976d2", "#bdbdbd"]
        
        ax.barh(categories, counts, color=colors_list)
        ax.set_xlabel("Number of Findings", fontsize=10)
        ax.set_title("CVE Coverage", fontsize=12, fontweight='bold')
        ax.set_xlim(0, max(counts) * 1.1 if counts else 1)
        
        for i, v in enumerate(counts):
            ax.text(v + 0.1, i, str(v), va='center', fontweight='bold')
        
        img_buffer = io.BytesIO()
        plt.savefig(img_buffer, format='png', dpi=100, bbox_inches='tight')
        img_buffer.seek(0)
        plt.close(fig)
        
        return img_buffer


class PDFReportGenerator:
    """Generate professional PDF security assessment reports"""
    
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self.cve_fetcher = CVEFetcher()
        self.chart_gen = ChartGenerator()
    
    def generate_pdf(self, scan_result: Dict) -> bytes:
        """Generate complete PDF report and return as bytes"""
        buffer = io.BytesIO()
        
        pdf = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=0.75*inch,
            leftMargin=0.75*inch,
            topMargin=0.75*inch,
            bottomMargin=0.75*inch,
            title="Security Assessment Report"
        )
        
        story = []
        
        # Title Page
        story.extend(self._build_cover_page(scan_result))
        story.append(PageBreak())
        
        # Executive Summary
        story.extend(self._build_executive_summary(scan_result))
        
        # Charts
        story.extend(self._build_charts_section(scan_result))
        story.append(PageBreak())
        
        # Findings
        story.extend(self._build_findings_section(scan_result))
        
        # Metadata
        story.extend(self._build_metadata_section(scan_result))
        
        # Build PDF
        pdf.build(story)
        
        buffer.seek(0)
        return buffer.getvalue()
    
    def _build_cover_page(self, scan_result: Dict) -> List:
        """Build cover page"""
        elements = []
        
        elements.append(Spacer(1, 1*inch))
        elements.append(Paragraph("Security Assessment Report", self.styles['Heading1']))
        elements.append(Spacer(1, 0.3*inch))
        elements.append(Paragraph("Web Security Scanner Assessment", self.styles['Normal']))
        elements.append(Spacer(1, 0.5*inch))
        
        # Risk Summary
        critical = len([f for f in scan_result.get("findings", []) if f.get("severity") == "Critical"])
        high = len([f for f in scan_result.get("findings", []) if f.get("severity") == "High"])
        medium = len([f for f in scan_result.get("findings", []) if f.get("severity") == "Medium"])
        low = len([f for f in scan_result.get("findings", []) if f.get("severity") == "Low"])
        
        summary_data = [
            ["Assessment Target", scan_result.get("final_url", "N/A")],
            ["Assessment Date", datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
            ["Overall Risk Grade", f"{scan_result.get('grade', 'N/A')} ({scan_result.get('score', 0)}/100)"],
            ["Critical Issues", str(critical)],
            ["High Issues", str(high)],
            ["Medium Issues", str(medium)],
            ["Low Issues", str(low)],
            ["Total Findings", str(len(scan_result.get("findings", [])))],
        ]
        
        summary_table = Table(summary_data, colWidths=[2*inch, 4*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor("#f5f5f5")),
            ('BACKGROUND', (1, 0), (1, -1), colors.HexColor("#fafafa")),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey),
        ]))
        elements.append(summary_table)
        
        return elements
    
    def _build_executive_summary(self, scan_result: Dict) -> List:
        """Build executive summary section"""
        elements = []
        
        elements.append(Paragraph("Executive Summary", self.styles['Heading2']))
        
        findings = scan_result.get("findings", [])
        critical = len([f for f in findings if f.get("severity") == "Critical"])
        high = len([f for f in findings if f.get("severity") == "High"])
        
        summary_text = f"""
        This automated security assessment of <b>{scan_result.get('final_url', 'N/A')}</b> identified 
        <b>{len(findings)}</b> potential security issues. The assessment includes <b>{critical}</b> critical 
        vulnerabilities and <b>{high}</b> high-severity issues that require immediate attention.
        <br/><br/>
        Overall security score: <b>{scan_result.get('score', 0)}/100</b> (Grade: <b>{scan_result.get('grade', 'N/A')}</b>)
        """
        
        elements.append(Paragraph(summary_text, self.styles['Normal']))
        elements.append(Spacer(1, 0.2*inch))
        
        return elements
    
    def _build_charts_section(self, scan_result: Dict) -> List:
        """Build charts section"""
        elements = []
        
        elements.append(Paragraph("Vulnerability Analysis", self.styles['Heading2']))
        
        findings = scan_result.get("findings", [])
        
        # Create charts
        severity_chart = self.chart_gen.create_severity_chart(findings)
        cve_chart = self.chart_gen.create_cve_chart(findings)
        
        # Add to PDF
        severity_img = Image(severity_chart, width=3*inch, height=2*inch)
        cve_img = Image(cve_chart, width=3*inch, height=2*inch)
        
        chart_table = Table([[severity_img, cve_img]])
        chart_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('TOPPADDING', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
        ]))
        elements.append(chart_table)
        elements.append(Spacer(1, 0.2*inch))
        
        return elements
    
    def _build_findings_section(self, scan_result: Dict) -> List:
        """Build detailed findings section"""
        elements = []
        
        findings = scan_result.get("findings", [])
        elements.append(Paragraph(f"Detailed Findings ({len(findings)})", self.styles['Heading2']))
        
        for idx, finding in enumerate(findings, 1):
            # Finding title with severity color
            severity = finding.get("severity", "Unknown")
            severity_color_map = {
                "Critical": "#d32f2f",
                "High": "#f57c00",
                "Medium": "#fbc02d",
                "Low": "#388e3c",
            }
            severity_color = severity_color_map.get(severity, "#999999")
            
            # Title
            elements.append(Paragraph(f"<b>{idx}. {finding.get('title', 'Unknown Issue')}</b>", self.styles['Heading3']))
            
            # Severity and CVE badges
            badge_text = f"<font color='{severity_color}'><b>[{severity.upper()}]</b></font>"
            if finding.get("cve"):
                cve_id = finding.get("cve")
                cve_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                badge_text += f" &nbsp; <a href='{cve_url}'><b>{cve_id}</b></a>"
            if finding.get("cvss_score"):
                badge_text += f" &nbsp; <font color='#424242'><b>CVSS: {finding.get('cvss_score')}</b></font>"
            
            elements.append(Paragraph(badge_text, self.styles['Normal']))
            elements.append(Spacer(1, 0.1*inch))
            
            # Description
            description = finding.get("description", "N/A")
            elements.append(Paragraph(f"<b>Description:</b> {description}", self.styles['Normal']))
            elements.append(Spacer(1, 0.1*inch))
            
            # Recommendation
            recommendation = finding.get("recommendation", "N/A")
            elements.append(Paragraph(f"<b>Remediation:</b> {recommendation}", self.styles['Normal']))
            elements.append(Spacer(1, 0.15*inch))
        
        return elements
    
    def _build_metadata_section(self, scan_result: Dict) -> List:
        """Build metadata footer"""
        elements = []
        
        elements.append(Spacer(1, 0.2*inch))
        elements.append(Paragraph("Report Information", self.styles['Heading2']))
        
        metadata = [
            ["Target URL", scan_result.get("final_url", "N/A")],
            ["Report Generated", datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
            ["Scanner", "anxextor Web Security Scanner"],
            ["Scan Duration", f"{scan_result.get('timing_ms', 0)}ms"],
        ]
        
        metadata_table = Table(metadata, colWidths=[2*inch, 4*inch])
        metadata_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor("#f5f5f5")),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey),
        ]))
        elements.append(metadata_table)
        
        elements.append(Spacer(1, 0.3*inch))
        
        # Consultant contact
        contact_text = """
        <b>For Security Consultation & Remediation Support</b><br/>
        <font color='#1976d2' size='12'><b>iam@sebastine.com</b></font><br/><br/>
        <i>This report is generated automatically and should be reviewed by security professionals.</i>
        """
        elements.append(Paragraph(contact_text, self.styles['Normal']))
        
        return elements


def generate_pdf_report(scan_result: Dict) -> bytes:
    """Generate PDF report from scan results"""
    generator = PDFReportGenerator()
    return generator.generate_pdf(scan_result)
