from node.adapters.models import Model
from node.transport.protocol import ProtocolError


class Ask(Model):
    question: str
    params: dict


def catalog_handler(catalog):
    def handle(peer, message):
        if message.type != "ask":
            raise ProtocolError("message_not_implemented", 400)
        try:
            body = Ask.model_validate(message.body)
        except Exception:
            raise ProtocolError("invalid_message_body", 400)
        try:
            return catalog.ask(peer, body.question, body.params)
        except (KeyError, ValueError):
            raise ProtocolError("invalid_parameters", 400)

    return handle
