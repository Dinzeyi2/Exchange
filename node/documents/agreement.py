from node.identity.crypto import digest


def agreement(trade):
    return (
        "ASSIGNMENT AND ASSUMPTION — REFERENCE TEMPLATE\n"
        "For demonstration only. Bank counsel must supply the operative agreement.\n\n"
        f"Trade: {trade['trade_id']}\nFacility: {trade['facility_id']}\n"
        f"Assignor: {trade['seller']}\nAssignee: {trade['buyer']}\n"
        f"Principal (USD cents): {trade['amount']}\nPrice (%): {trade['price']}\n"
        f"Trade date: {trade['trade_date']}\nEffective date: {trade['settlement_date']}\n"
    )


def document_hash(trade):
    return digest({"text": agreement(trade)})
