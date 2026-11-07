"""Dedicated peer listener. Local REST API is never mounted on this listener."""

import asyncio
import hashlib
import json

import h11

from node.identity.crypto import canonical
from node.transport.protocol import ProtocolError, envelope


async def serve(transport, context, host="0.0.0.0", port=8443):
    async def connection(reader, writer):
        conn = h11.Connection(h11.SERVER, max_incomplete_event_size=16384)
        body = bytearray()
        request = None
        raw = {}
        deadline = asyncio.get_running_loop().time() + 15
        try:
            while True:
                data = await asyncio.wait_for(
                    reader.read(65536),
                    max(0, deadline - asyncio.get_running_loop().time()),
                )
                if not data:
                    return
                conn.receive_data(data)
                while True:
                    ev = conn.next_event()
                    if ev is h11.NEED_DATA:
                        break
                    if isinstance(ev, h11.Request):
                        request = ev
                    elif isinstance(ev, h11.Data):
                        body.extend(ev.data)
                        if len(body) > 25 * 1024 * 1024:
                            raise ProtocolError("body_too_large", 413)
                    elif isinstance(ev, h11.EndOfMessage):
                        cert = writer.get_extra_info("ssl_object").getpeercert(
                            binary_form=True
                        )
                        pin = hashlib.sha256(cert).hexdigest()
                        if pin not in {
                            p.certificate_sha256 for p in transport.peers.values()
                        }:
                            raise ProtocolError("unpinned_certificate")
                        if request.method == b"GET" and request.target == b"/v1/health":
                            result = {"status": "ok"}
                        elif (
                            request.method == b"POST"
                            and request.target == b"/v1/envelope"
                        ):
                            raw = json.loads(
                                body,
                                parse_constant=lambda value: (_ for _ in ()).throw(
                                    ValueError("non-finite number")
                                ),
                            )
                            if len(body) > 1024 * 1024 and (
                                not isinstance(raw, dict)
                                or raw.get("type")
                                not in ["kyc.release", "local.import"]
                            ):
                                raise ProtocolError("body_too_large", 413)
                            result = await asyncio.to_thread(
                                transport.receive, raw, pin
                            )
                        else:
                            raise ProtocolError("not_found", 404)
                        await respond(writer, conn, 200, result)
                        return
                    elif isinstance(ev, h11.ConnectionClosed):
                        return
        except (
            ProtocolError,
            ValueError,
            h11.RemoteProtocolError,
            asyncio.TimeoutError,
        ) as error:
            try:
                recipient = (
                    raw.get("from", "unknown") if isinstance(raw, dict) else "unknown"
                )
                trade_id = raw.get("trade_id", "") if isinstance(raw, dict) else ""
                nonce = raw.get("nonce", "") if isinstance(raw, dict) else ""
                signed = envelope(
                    transport.signer,
                    transport.node_id,
                    str(recipient)[:100],
                    "error",
                    str(trade_id)[:80],
                    {
                        "request_nonce": str(nonce)[:32],
                        "error": getattr(error, "code", "invalid_request"),
                    },
                )
                with transport.store.transaction() as s:
                    transport.store.audit(
                        s, "transport.error", signed, "out", str(recipient)[:100]
                    )
                await respond(writer, conn, getattr(error, "status", 400), signed)
            except Exception:
                pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    return await asyncio.start_server(
        connection, host, port, ssl=context, ssl_handshake_timeout=10
    )


async def respond(writer, conn, status, result):
    payload = canonical(result)
    writer.write(
        conn.send(
            h11.Response(
                status_code=status,
                headers=[
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(payload)).encode()),
                    (b"connection", b"close"),
                ],
            )
        )
    )
    writer.write(conn.send(h11.Data(data=payload)))
    writer.write(conn.send(h11.EndOfMessage()))
    await writer.drain()
