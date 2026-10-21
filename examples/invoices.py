"""Synthetic review fixture. No real account or invoice data."""


def get_invoice(invoices, user_id, invoice_id):
    invoice = invoices.get(invoice_id)
    if invoice is None:
        return None
    return invoice
