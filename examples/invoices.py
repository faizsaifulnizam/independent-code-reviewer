"""Synthetic review fixture. No real account or invoice data."""


def get_invoice(invoices, user_id, invoice_id):
    invoice = invoices.get(invoice_id)
    if invoice is None or invoice["owner_id"] != user_id:
        return None
    return invoice
