import asyncio
import ssl

from node.audit.store import Store
from node.transport.protocol import Transport, tls_context
from node.transport.server import serve
from sim.certificates import identity
from sim.network import exercise


def test_four_node_tls(tmp_path):
    report = asyncio.run(exercise(tmp_path))
    assert report["samples"] == 20 and report["audit_chains_valid"]


def test_tls_client_certificate_required(tmp_path):
    async def run():
        peer, signer, _, cert, key = identity(tmp_path, "agent", 0)
        client, _, _, client_cert, _ = identity(tmp_path, "seller", 0)
        transport = Transport(
            "agent",
            signer,
            Store("sqlite:///" + str(tmp_path / "p.db")),
            {"seller": client},
            lambda p, m: {},
        )
        server = await serve(
            transport, tls_context(cert, key, [client_cert]), host="127.0.0.1", port=0
        )
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
            context.load_verify_locations(cert)
            reader, writer = await asyncio.open_connection(
                "localhost", server.sockets[0].getsockname()[1], ssl=context
            )
            writer.write(b"GET /v1/health HTTP/1.1\r\nHost: localhost\r\n\r\n")
            try:
                await writer.drain()
                assert await asyncio.wait_for(reader.read(1024), 2) == b""
            except (ssl.SSLError, ConnectionResetError):
                pass
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(run())
