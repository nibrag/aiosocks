import asyncio
import struct
import socket
from aiohttp.test_utils import unused_port


class FakeSocksSrv:
    def __init__(self, loop, write_buff):
        self._loop = loop
        self._write_buff = write_buff
        self._transports = []
        self._srv = None
        self.port = unused_port()

    async def __aenter__(self):
        transports = self._transports
        write_buff = self._write_buff

        class SocksPrimitiveProtocol(asyncio.Protocol):
            _transport = None

            def connection_made(self, transport):
                self._transport = transport
                transports.append(transport)

            def data_received(self, data):
                self._transport.write(write_buff)

        def factory():
            return SocksPrimitiveProtocol()

        self._srv = await self._loop.create_server(
            factory, '127.0.0.1', self.port)

        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        for tr in self._transports:
            tr.close()

        self._srv.close()
        await self._srv.wait_closed()


class FakeSocks4Srv:
    def __init__(self, loop):
        self._loop = loop
        self._transports = []
        self._futures = []
        self._srv = None
        self.port = unused_port()

    async def __aenter__(self):
        transports = self._transports
        futures = self._futures

        class Socks4Protocol(asyncio.StreamReaderProtocol):
            def __init__(self, _loop):
                self._loop = _loop
                reader = asyncio.StreamReader(loop=self._loop)
                super().__init__(reader, client_connected_cb=self.negotiate,
                                 loop=self._loop)

            def connection_made(self, transport):
                transports.append(transport)
                super().connection_made(transport)

            async def negotiate(self, reader, writer):
                writer.write(b'\x00\x5a\x04W\x01\x01\x01\x01')

                data = await reader.read(9)

                dst_port = struct.unpack('>H', data[2:4])[0]
                dst_addr = data[4:8]

                if data[-1] != 0x00:
                    while True:
                        byte = await reader.read(1)
                        if byte == 0x00:
                            break

                if dst_addr == b'\x00\x00\x00\x01':
                    dst_addr = bytearray()

                    while True:
                        byte = await reader.read(1)
                        if byte == 0x00:
                            break
                        dst_addr.append(byte)
                else:
                    dst_addr = socket.inet_ntoa(dst_addr)

                cl_reader, cl_writer = await asyncio.open_connection(
                    host=dst_addr, port=dst_port, loop=self._loop
                )
                transports.append(cl_writer)

                cl_fut = asyncio.ensure_future(
                    self.retranslator(reader, cl_writer), loop=self._loop)
                dst_fut = asyncio.ensure_future(
                    self.retranslator(cl_reader, writer), loop=self._loop)

                futures.append(cl_fut)
                futures.append(dst_fut)

            async def retranslator(self, reader, writer):
                data = bytearray()
                while True:
                    try:
                        byte = await reader.read(10)
                        if not byte:
                            break
                        data.append(byte[0])
                        writer.write(byte)
                        await writer.drain()
                    except:  # noqa
                        break

        def factory():
            return Socks4Protocol(_loop=self._loop)

        self._srv = await self._loop.create_server(
            factory, '127.0.0.1', self.port)

        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        for tr in self._transports:
            tr.close()

        self._srv.close()
        await self._srv.wait_closed()

        for f in self._futures:
            if not f.cancelled() or not f.done():
                f.cancel()
