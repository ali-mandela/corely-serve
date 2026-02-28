"""
Invoice PDF Generation Service for Enterprise Sales Module
"""
from typing import Optional, Dict, Any
from datetime import datetime
from decimal import Decimal
import io
import os
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas
from reportlab.lib.enums import TA_CENTER, TA_RIGHT, TA_LEFT

from app._schemas.sale_schema import SaleResponse


class InvoiceService:
    """Service for generating professional PDF invoices"""

    def __init__(self):
        self.styles = getSampleStyleSheet()
        self.setup_custom_styles()

    def setup_custom_styles(self):
        """Setup custom paragraph styles"""
        # Company header style
        self.styles.add(ParagraphStyle(
            name='CompanyHeader',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1f2937'),
            alignment=TA_CENTER,
            spaceAfter=12
        ))

        # Invoice title style
        self.styles.add(ParagraphStyle(
            name='InvoiceTitle',
            parent=self.styles['Heading2'],
            fontSize=18,
            textColor=colors.HexColor('#3b82f6'),
            alignment=TA_RIGHT,
            spaceBefore=6,
            spaceAfter=6
        ))

        # Address style
        self.styles.add(ParagraphStyle(
            name='Address',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=colors.HexColor('#4b5563'),
            spaceAfter=4
        ))

        # Table header style
        self.styles.add(ParagraphStyle(
            name='TableHeader',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=colors.white,
            alignment=TA_CENTER
        ))

    async def generate_invoice_pdf(self,
                                 sale: SaleResponse,
                                 company_info: Dict[str, Any],
                                 store_info: Dict[str, Any],
                                 customer_info: Optional[Dict[str, Any]] = None) -> bytes:
        """Generate a professional PDF invoice"""

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=72, leftMargin=72,
                              topMargin=72, bottomMargin=18)

        # Build the PDF content
        story = []

        # Company header
        story.append(Paragraph(company_info.get('name', 'Your Company'),
                              self.styles['CompanyHeader']))

        # Company details
        company_address = f"""
        {company_info.get('address', '')}<br/>
        {company_info.get('city', '')}, {company_info.get('state', '')} {company_info.get('zip_code', '')}<br/>
        Phone: {company_info.get('phone', '')}<br/>
        Email: {company_info.get('email', '')}
        """
        story.append(Paragraph(company_address, self.styles['Address']))
        story.append(Spacer(1, 20))

        # Invoice header with invoice number and date
        invoice_header_data = [
            ['', 'INVOICE'],
            ['', f'#{sale.invoice_number}'],
            ['', f'Date: {sale.sale_date.strftime("%B %d, %Y") if hasattr(sale.sale_date, "strftime") else sale.sale_date}']
        ]

        invoice_header = Table(invoice_header_data, colWidths=[4*inch, 2*inch])
        invoice_header.setStyle(TableStyle([
            ('ALIGN', (1, 0), (1, -1), 'RIGHT'),
            ('FONTNAME', (1, 0), (1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (1, 0), (1, 0), 18),
            ('TEXTCOLOR', (1, 0), (1, 0), colors.HexColor('#3b82f6')),
            ('FONTNAME', (1, 1), (1, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (1, 1), (1, -1), 12),
        ]))
        story.append(invoice_header)
        story.append(Spacer(1, 20))

        # Store and customer information
        info_data = []

        # Store info (left column)
        store_address = f"""
        <b>FROM:</b><br/>
        {store_info.get('name', 'Store Name')}<br/>
        {store_info.get('address', {}).get('street', '')}<br/>
        {store_info.get('address', {}).get('city', '')}, {store_info.get('address', {}).get('state', '')} {store_info.get('address', {}).get('zip_code', '')}<br/>
        Phone: {store_info.get('phone', '')}
        """

        # Customer info (right column)
        if customer_info:
            customer_address = f"""
            <b>TO:</b><br/>
            {customer_info.get('name', 'Customer')}<br/>
            {customer_info.get('address', {}).get('street', '') if customer_info.get('address') else ''}<br/>
            {customer_info.get('address', {}).get('city', '') if customer_info.get('address') else ''}, {customer_info.get('address', {}).get('state', '') if customer_info.get('address') else ''} {customer_info.get('address', {}).get('zip_code', '') if customer_info.get('address') else ''}<br/>
            Phone: {customer_info.get('phone', '')}
            """
        else:
            customer_address = """
            <b>TO:</b><br/>
            Walk-in Customer
            """

        info_table = Table([[store_address, customer_address]], colWidths=[3*inch, 3*inch])
        info_table.setStyle(TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('LEFTPADDING', (0, 0), (-1, -1), 0),
            ('RIGHTPADDING', (0, 0), (-1, -1), 0),
        ]))
        story.append(info_table)
        story.append(Spacer(1, 30))

        # Items table
        items_data = [['Description', 'SKU', 'Qty', 'Unit Price', 'Discount', 'Total']]

        for item in sale.items:
            items_data.append([
                item.product_name or 'Product',
                item.product_sku or 'N/A',
                str(item.quantity),
                f'${float(item.unit_price):.2f}',
                f'${float(item.discount):.2f}' if item.discount > 0 else '-',
                f'${float(item.total):.2f}'
            ])

        items_table = Table(items_data, colWidths=[2.2*inch, 1*inch, 0.7*inch, 1*inch, 0.8*inch, 1*inch])
        items_table.setStyle(TableStyle([
            # Header row
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3b82f6')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),

            # Data rows
            ('ALIGN', (2, 1), (-1, -1), 'RIGHT'),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f9fafb')]),

            # Borders
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e5e7eb')),
            ('LINEBELOW', (0, 0), (-1, 0), 2, colors.HexColor('#3b82f6')),
        ]))
        story.append(items_table)
        story.append(Spacer(1, 20))

        # Totals section
        totals_data = [
            ['Subtotal:', f'${float(sale.subtotal):.2f}'],
            ['Tax:', f'${float(sale.tax_amount):.2f}'],
            ['Discount:', f'-${float(sale.discount_amount):.2f}'] if sale.discount_amount > 0 else ['', ''],
            ['<b>Total:</b>', f'<b>${float(sale.total_amount):.2f}</b>'],
        ]

        # Filter out empty discount row
        totals_data = [row for row in totals_data if row[0]]

        totals_table = Table(totals_data, colWidths=[4.5*inch, 1.5*inch])
        totals_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'RIGHT'),
            ('FONTNAME', (0, -1), (-1, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 12),
            ('LINEABOVE', (0, -1), (-1, -1), 2, colors.HexColor('#3b82f6')),
            ('TOPPADDING', (0, -1), (-1, -1), 8),
        ]))
        story.append(totals_table)
        story.append(Spacer(1, 30))

        # Payment information
        payment_info = f"""
        <b>Payment Method:</b> {sale.payment_method.value.title()}<br/>
        <b>Payment Status:</b> {sale.payment_status.value.title() if hasattr(sale, 'payment_status') else 'Paid'}
        """
        story.append(Paragraph(payment_info, self.styles['Normal']))

        if sale.notes:
            story.append(Spacer(1, 20))
            story.append(Paragraph(f"<b>Notes:</b> {sale.notes}", self.styles['Normal']))

        # Footer
        story.append(Spacer(1, 30))
        footer_text = f"""
        <para align=center>
        <i>Thank you for your business!</i><br/>
        Generated on {datetime.now().strftime("%B %d, %Y at %I:%M %p")}
        </para>
        """
        story.append(Paragraph(footer_text, self.styles['Normal']))

        # Build PDF
        doc.build(story)
        buffer.seek(0)
        return buffer.getvalue()

    def generate_receipt_pdf(self,
                           sale: SaleResponse,
                           store_info: Dict[str, Any],
                           customer_info: Optional[Dict[str, Any]] = None) -> bytes:
        """Generate a simple receipt PDF (smaller format)"""

        buffer = io.BytesIO()
        # Use smaller page size for receipts
        doc = SimpleDocTemplate(buffer, pagesize=(4*inch, 6*inch),
                              rightMargin=18, leftMargin=18, topMargin=18, bottomMargin=18)

        story = []

        # Store header
        story.append(Paragraph(store_info.get('name', 'Store'),
                              self.styles['Heading2']))
        story.append(Paragraph(store_info.get('phone', ''),
                              self.styles['Normal']))
        story.append(Spacer(1, 10))

        # Receipt details
        story.append(Paragraph(f"Receipt: {sale.invoice_number}",
                              self.styles['Normal']))
        story.append(Paragraph(f"Date: {datetime.now().strftime('%m/%d/%Y %I:%M %p')}",
                              self.styles['Normal']))
        story.append(Spacer(1, 10))

        # Simple items list
        for item in sale.items:
            item_text = f"{item.quantity}x {item.product_name or 'Item'} @ ${float(item.unit_price):.2f} = ${float(item.total):.2f}"
            story.append(Paragraph(item_text, self.styles['Normal']))

        story.append(Spacer(1, 10))
        story.append(Paragraph(f"Subtotal: ${float(sale.subtotal):.2f}", self.styles['Normal']))
        story.append(Paragraph(f"Tax: ${float(sale.tax_amount):.2f}", self.styles['Normal']))
        story.append(Paragraph(f"<b>Total: ${float(sale.total_amount):.2f}</b>", self.styles['Normal']))

        story.append(Spacer(1, 10))
        story.append(Paragraph("Thank you!", self.styles['Normal']))

        doc.build(story)
        buffer.seek(0)
        return buffer.getvalue()