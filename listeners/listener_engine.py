#!/usr/bin/env python3
"""
    XEEA Nexus - C2 Listener Engine
    Multi-protocol listener manager for handling incoming connections.
"""

import asyncio
import logging
from rich.console import Console

console = Console()

class NexusListener:
    def __init__(self, name, host, port):
        self.name = name
        self.host = host
        self.port = port
        self.server = None
        self.is_running = False

    async def handle_connection(self, reader, writer):
        addr = writer.get_extra_info('peername')
        logging.info(f"[*] Incoming connection from {addr} on {self.name}")
        # Standard XEEA Handshake logic goes here
        writer.close()
        await writer.wait_closed()

    async def start(self):
        self.server = await asyncio.start_server(self.handle_connection, self.host, self.port)
        self.is_running = True
        addr = self.server.sockets[0].getsockname()
        logging.info(f"[+] {self.name} started on {addr}")
        async with self.server:
            await self.server.serve_forever()

    def stop(self):
        if self.server:
            self.server.close()
            self.is_running = False
            logging.info(f"[-] {self.name} stopped.")

class ListenerManager:
    def __init__(self):
        self.listeners = {}
        self.loop = asyncio.get_event_loop()

    def add_listener(self, name, host, port):
        listener = NexusListener(name, host, port)
        self.listeners[name] = listener
        return listener

    async def start_all(self):
        tasks = [l.start() for l in self.listeners.values()]
        await asyncio.gather(*tasks)

if __name__ == "__main__":
    # Internal test
    mgr = ListenerManager()
    mgr.add_listener("HTTP_BEACON", "0.0.0.0", 8080)
    try:
        asyncio.run(mgr.start_all())
    except KeyboardInterrupt:
        pass
