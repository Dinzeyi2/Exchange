import base64
import hashlib
import http.client
import json
from datetime import datetime, timezone
from urllib.parse import urlsplit

from node.identity.crypto import canonical, verify
from node.transport.protocol import ProtocolError


def send(peer, message, context):
    url = urlsplit(peer.endpoint)
    if (
        url.scheme != "https"
        or url.username
        or url.password
        or url.query
        or url.fragment
    ):
        raise ValueError("peer endpoint must be HTTPS")
    connection = http.client.HTTPSConnection(
        url.hostname, url.port or 443, context=context, timeout=10
    )
    try:
        connection.connect()
        actual = hashlib.sha256(
            connection.sock.getpeercert(binary_form=True)
        ).hexdigest()
        if actual != peer.certificate_sha256:
            raise ProtocolError("unpinned_certificate")
        connection.request(
            "POST",
            "/v1/envelope",
            body=canonical(message),
            headers={"Content-Type": "application/json"},
        )
        response = connection.getresponse()
        payload = response.read(1024 * 1024 + 1)
        if len(payload) > 1024 * 1024:
            raise ProtocolError("peer_response_invalid")
        result = json.loads(payload)
        try:
            verify(
                base64.b64decode(peer.signing_key, validate=True),
                {k: v for k, v in result.items() if k != "sig"},
                result["sig"],
            )
            stamp = datetime.fromisoformat(result["ts"].replace("Z", "+00:00"))
            if (
                result["from"] != peer.node_id
                or result["to"] != message["from"]
                or result["trade_id"] != message["trade_id"]
                or result["v"] != 1
                or result["body"]["request_nonce"] != message["nonce"]
                or abs((datetime.now(timezone.utc) - stamp).total_seconds()) > 120
            ):
                raise ValueError("response binding mismatch")
        except Exception:
            raise ProtocolError("invalid_signed_response")
        if (
            result.get("type") not in ["answer", "error"]
            or response.status != 200
            and result.get("type") != "error"
        ):
            raise ProtocolError("peer_response_invalid")
        return result
    finally:
        connection.close()
