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
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor("#1a237e")),
            ('BACKGROUND', (1, 0), (1, -1), colors.HexColor("#eceff1")),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.white),
            ('TEXTCOLOR', (1, 0), (1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
            ('TOPPADDING', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor("#1976d2")),
            ('ROWBACKGROUNDS', (1, 0), (1, -1), [colors.HexColor("#eceff1"), colors.HexColor("#f5f5f5")]),
        ]))
        elements.append(summary_table)
        
        return elements
    
    def _build_executive_summary(self, scan_result: Dict) -> List:
        """Build executive summary section"""
        elements = []
        
        # Section header
        header_text = Paragraph("📋 Executive Summary", self.styles['Heading2'])
        header_table = Table([[header_text]], colWidths=[6*inch])
        header_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#1a237e")),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('TOPPADDING', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
            ('LEFTPADDING', (0, 0), (-1, -1), 12),
            ('BORDER', (0, 0), (-1, -1), 2, colors.HexColor("#0d47a1")),
        ]))
        elements.append(header_table)
        elements.append(Spacer(1, 0.1*inch))
        
        findings = scan_result.get("findings", [])
        critical = len([f for f in findings if f.get("severity") == "Critical"])
        high = len([f for f in findings if f.get("severity") == "High"])
        
        summary_text = f"""
        <b style='color:#1a237e'>Assessment Scope:</b><br/>
        This automated security assessment of <b style='color:#1976d2'>{scan_result.get('final_url', 'N/A')}</b> identified 
        <b style='color:#d32f2f'>{len(findings)}</b> potential security issues:<br/>
        <font color='#d32f2f'><b>● {critical} Critical</b></font> | 
        <font color='#f57c00'><b>● {high} High</b></font><br/><br/>
        <b style='color:#1a237e'>Overall Risk Assessment:</b><br/>
        Security Score: <b style='color:#1976d2'>{scan_result.get('score', 0)}/100</b> | 
        Grade: <b style='color:#1976d2'>{scan_result.get('grade', 'N/A')}</b>
        """
        
        # Summary box with colored background and border
        summary_data = [[Paragraph(summary_text, self.styles['Normal'])]]
        summary_table = Table(summary_data, colWidths=[6*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f5f9ff")),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('LEFTPADDING', (0, 0), (-1, -1), 14),
            ('RIGHTPADDING', (0, 0), (-1, -1), 14),
            ('TOPPADDING', (0, 0), (-1, -1), 14),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 14),
            ('BORDER', (0, 0), (-1, -1), 3, colors.HexColor("#1976d2")),
        ]))
        elements.append(summary_table)
        elements.append(Spacer(1, 0.2*inch))
        
        return elements
    
    def _build_charts_section(self, scan_result: Dict) -> List:
        """Build charts section"""
        elements = []
        
        # Section header with styling
        header_text = Paragraph("📊 Vulnerability Analysis", self.styles['Heading2'])
        header_table = Table([[header_text]], colWidths=[6*inch])
        header_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#1a237e")),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('TOPPADDING', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
            ('LEFTPADDING', (0, 0), (-1, -1), 12),
            ('BORDER', (0, 0), (-1, -1), 2, colors.HexColor("#0d47a1")),
        ]))
        elements.append(header_table)
        elements.append(Spacer(1, 0.1*inch))
        
        findings = scan_result.get("findings", [])
        
        # Create charts
        severity_chart = self.chart_gen.create_severity_chart(findings)
        cve_chart = self.chart_gen.create_cve_chart(findings)
        
        # Add to PDF
        severity_img = Image(severity_chart, width=3*inch, height=2*inch)
        cve_img = Image(cve_chart, width=3*inch, height=2*inch)
        
        chart_table = Table([[severity_img, cve_img]], colWidths=[3*inch, 3*inch])
        chart_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
            ('LEFTPADDING', (0, 0), (-1, -1), 5),
            ('RIGHTPADDING', (0, 0), (-1, -1), 5),
        ]))
        
        # Wrap charts in colored container
        chart_container = Table([[chart_table]], colWidths=[6*inch])
        chart_container.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f5f9ff")),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('BORDER', (0, 0), (-1, -1), 3, colors.HexColor("#1976d2")),
            ('TOPPADDING', (0, 0), (-1, -1), 12),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('LEFTPADDING', (0, 0), (-1, -1), 12),
            ('RIGHTPADDING', (0, 0), (-1, -1), 12),
        ]))
        elements.append(chart_container)
        elements.append(Spacer(1, 0.2*inch))
        
        return elements
    
    def _build_findings_section(self, scan_result: Dict) -> List:
        """Build detailed findings section"""
        elements = []
        
        findings = scan_result.get("findings", [])
        
        # Section header with styling
        header_text = Paragraph(f"🔍 Detailed Findings ({len(findings)})", self.styles['Heading2'])
        header_table = Table([[header_text]], colWidths=[6*inch])
        header_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#1a237e")),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('TOPPADDING', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
            ('LEFTPADDING', (0, 0), (-1, -1), 12),
            ('BORDER', (0, 0), (-1, -1), 2, colors.HexColor("#0d47a1")),
        ]))
        elements.append(header_table)
        elements.append(Spacer(1, 0.15*inch))
        
        # Severity color mapping with background colors
        severity_colors = {
            "Critical": {"text": "#d32f2f", "bg": "#ffebee", "border": "#c62828"},
            "High": {"text": "#f57c00", "bg": "#fff3e0", "border": "#e65100"},
            "Medium": {"text": "#f57f17", "bg": "#fffde7", "border": "#f9a825"},
            "Low": {"text": "#388e3c", "bg": "#e8f5e9", "border": "#2e7d32"},
        }
        for idx, finding in enumerate(findings, 1):
            severity = finding.get("severity", "Unknown")
            color_scheme = severity_colors.get(severity, {"text": "#333", "bg": "#f5f5f5", "border": "#999"})
            
            # Finding container with colored background and darker text for visibility
            # Use darker text color for light backgrounds
            text_color = "#0d47a1" if color_scheme['bg'] in ["#fffde7", "#fff3e0", "#f5f5f5"] else color_scheme['text']
            
            finding_data = [
                [
                    Paragraph(
                        f"<b style='color:{text_color}'>{idx}. {finding.get('title', 'Unknown Issue')}</b>",
                        self.styles['Heading3']
                    )
                ]
            ]
            finding_table = Table(finding_data, colWidths=[6*inch])
            finding_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor(color_scheme['bg'])),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('LEFTPADDING', (0, 0), (-1, -1), 12),
                ('RIGHTPADDING', (0, 0), (-1, -1), 12),
                ('TOPPADDING', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
                ('BORDER', (0, 0), (-1, -1), 3, colors.HexColor(color_scheme['border'])),
            ]))
            elements.append(finding_table)
            elements.append(Spacer(1, 0.08*inch))
            
            # Badges
            badge_text = f"<font color='{color_scheme['text']}'><b>● {severity.upper()}</b></font>"
            if finding.get("cve"):
                cve_id = finding.get("cve")
                cve_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                badge_text += f" &nbsp; <font color='#1976d2'><a href='{cve_url}'><b>CVE: {cve_id}</b></a></font>"
            if finding.get("cvss_score"):
                cvss = finding.get("cvss_score")
                cvss_color = "#d32f2f" if cvss >= 7 else "#f57c00" if cvss >= 4 else "#388e3c"
                badge_text += f" &nbsp; <font color='{cvss_color}'><b>CVSS {cvss}</b></font>"
            
            elements.append(Paragraph(badge_text, self.styles['Normal']))
            elements.append(Spacer(1, 0.08*inch))
            
            # Description
            description = finding.get("description", "N/A")
            desc_data = [[Paragraph(f"<b style='color:#1a237e'>📋 Description:</b><br/>{description}", self.styles['Normal'])]]
            desc_table = Table(desc_data, colWidths=[5.8*inch])
            desc_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#fafafa")),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('LEFTPADDING', (0, 0), (-1, -1), 10),
                ('RIGHTPADDING', (0, 0), (-1, -1), 10),
                ('TOPPADDING', (0, 0), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ('BORDER', (0, 0), (-1, -1), 1, colors.HexColor("#ccc")),
            ]))
            elements.append(desc_table)
            elements.append(Spacer(1, 0.1*inch))
            
            # Recommendation - with colored box and strong border
            recommendation = finding.get("recommendation", "N/A")
            rec_data = [[Paragraph(f"<b style='color:#1a237e'>✓ Remediation:</b><br/>{recommendation}", self.styles['Normal'])]]
            rec_table = Table(rec_data, colWidths=[5.8*inch])
            rec_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#e3f2fd")),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('LEFTPADDING', (0, 0), (-1, -1), 10),
                ('RIGHTPADDING', (0, 0), (-1, -1), 10),
                ('TOPPADDING', (0, 0), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ('BORDER', (0, 0), (-1, -1), 2, colors.HexColor("#1976d2")),
            ]))
            elements.append(rec_table)
            elements.append(Spacer(1, 0.2*inch))
        
        return elements
    
    def _build_metadata_section(self, scan_result: Dict) -> List:
        """Build metadata footer"""
        elements = []
        
        elements.append(Spacer(1, 0.2*inch))
        
        # Section header with styling
        header_text = Paragraph("📋 Report Information", self.styles['Heading2'])
        header_table = Table([[header_text]], colWidths=[6*inch])
        header_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#1a237e")),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('TOPPADDING', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
            ('LEFTPADDING', (0, 0), (-1, -1), 12),
            ('BORDER', (0, 0), (-1, -1), 2, colors.HexColor("#0d47a1")),
        ]))
        elements.append(header_table)
        elements.append(Spacer(1, 0.1*inch))
        
        metadata = [
            ["Target URL", scan_result.get("final_url", "N/A")],
            ["Report Generated", datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
            ["Scanner", "anxextor Web Security Scanner"],
            ["Scan Duration", f"{scan_result.get('timing_ms', 0)}ms"],
        ]
        
        metadata_table = Table(metadata, colWidths=[2*inch, 4*inch])
        metadata_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor("#1a237e")),
            ('BACKGROUND', (1, 0), (1, -1), colors.HexColor("#eceff1")),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.white),
            ('TEXTCOLOR', (1, 0), (1, -1), colors.black),
            ('ALIGN', (0, 0), (0, -1), 'LEFT'),
            ('ALIGN', (1, 0), (1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
            ('TOPPADDING', (0, 0), (-1, -1), 10),
            ('LEFTPADDING', (0, 0), (-1, -1), 10),
            ('RIGHTPADDING', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 2, colors.HexColor("#1976d2")),
            ('ROWBACKGROUNDS', (1, 0), (1, -1), [colors.HexColor("#eceff1"), colors.HexColor("#f5f5f5")]),
        ]))
        elements.append(metadata_table)
        
        elements.append(Spacer(1, 0.3*inch))
        
        # Consultant contact with colored background and strong border
        contact_data = [[
            Paragraph(
                """<b style='color:#1a237e'>🔒 Security Consultation & Remediation Support</b><br/>
                <font color='#1976d2' size='12'><b>iam@sebastine.com</b></font><br/>
                <i style='color:#555'>This report is generated automatically and should be reviewed by security professionals.</i>""",
                self.styles['Normal']
            )
        ]]
        contact_table = Table(contact_data, colWidths=[6*inch])
        contact_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f5f9ff")),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('LEFTPADDING', (0, 0), (-1, -1), 15),
            ('RIGHTPADDING', (0, 0), (-1, -1), 15),
            ('TOPPADDING', (0, 0), (-1, -1), 12),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('BORDER', (0, 0), (-1, -1), 3, colors.HexColor("#1976d2")),
        ]))
        elements.append(contact_table)
        
        return elements


def generate_pdf_report(scan_result: Dict) -> bytes:
    """Generate PDF report from scan results"""
    generator = PDFReportGenerator()
    return generator.generate_pdf(scan_result)
