import asyncio
import logging
import signal

from node.runtime.config import Settings
from node.runtime.payments import export_one, ingest_one
from node.runtime.service import Node
from node.transport.protocol import tls_context
from node.transport.server import serve

log = logging.getLogger("exchange")


async def run(config):
    settings = Settings.load(config)
    node = Node(settings)
    api_app = None
    if settings.oidc:
        from node.api.local import create_app

        api_app = create_app(node)
    peer_tls = tls_context(
        settings.certificate,
        settings.tls_key,
        [p.certificate_path for p in settings.peers],
    )
    local_tls = tls_context(
        settings.certificate,
        settings.tls_key,
        [o.certificate_path for o in settings.officers],
    )
    peer = await serve(node.transport, peer_tls, settings.peer_host, settings.peer_port)
    local = await serve(
        node.local_transport, local_tls, settings.officer_host, settings.officer_port
    )
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in [signal.SIGTERM, signal.SIGINT]:
        loop.add_signal_handler(sig, stop.set)

    async def worker():
        last_audit = loop.time()
        while not stop.is_set():
            try:
                sent = await asyncio.to_thread(node.dispatch_one)
                await asyncio.to_thread(node.check_one)
                await asyncio.to_thread(ingest_one, node)
                await asyncio.to_thread(export_one, node)
                if loop.time() - last_audit >= 3600:
                    if not await asyncio.to_thread(node.store.verify_audit_chain):
                        log.critical("audit_chain_invalid; stopping node")
                        stop.set()
                    last_audit = loop.time()
                if not sent:
                    try:
                        await asyncio.wait_for(stop.wait(), 0.05)
                    except asyncio.TimeoutError:
                        pass
            except Exception as error:
                # Counts/codes only; never log payment XML, KYC, SSI, envelopes or key values.
                log.error("worker_operation_failed %s", type(error).__name__)
                await asyncio.sleep(0.2)

    task = asyncio.create_task(worker())
    api_task = None
    api_server = None
    if settings.oidc:
        import uvicorn

        api_server = uvicorn.Server(
            uvicorn.Config(
                api_app,
                host=settings.api_host,
                port=settings.api_port,
                access_log=False,
                log_level="warning",
            )
        )
        api_task = asyncio.create_task(api_server.serve())
    try:
        if not node.store.verify_audit_chain():
            raise RuntimeError("audit_chain_invalid")
        print(
            f"Exchange {settings.node_id} role={settings.role} peer_port={settings.peer_port} officer_port={settings.officer_port}",
            flush=True,
        )
        await stop.wait()
    finally:
        if api_server:
            api_server.should_exit = True
            await api_task
        await task
        for server in [peer, local]:
            server.close()
            await server.wait_closed()
        node.pool.shutdown(wait=True, cancel_futures=True)
        node.store.engine.dispose()
