import asyncio
import aiohttp
import contextlib
import gc
import os
import socket
import ssl
import struct
import threading
from unittest import mock
from aiohttp.server import ServerHttpProtocol
try:
    from asyncio import ensure_future
except ImportError:
    ensure_future = asyncio.async


def fake_coroutine(return_value):
    def coro(*args, **kwargs):
        if isinstance(return_value, Exception):
            raise return_value
        return return_value

    return mock.Mock(side_effect=asyncio.coroutine(coro))


def find_unused_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port


@contextlib.contextmanager
def fake_socks_srv(loop, write_buff):
    transports = []

    class SocksPrimitiveProtocol(asyncio.Protocol):
        _transport = None

        def connection_made(self, transport):
            self._transport = transport
            transports.append(transport)

        def data_received(self, data):
            self._transport.write(write_buff)

    port = find_unused_port()

    def factory():
        return SocksPrimitiveProtocol()

    srv = loop.run_until_complete(
        loop.create_server(factory, '127.0.0.1', port))

    yield port

    for tr in transports:
        tr.close()

    srv.close()
    loop.run_until_complete(srv.wait_closed())
    gc.collect()


@contextlib.contextmanager
def fake_socks4_srv(loop):
    port = find_unused_port()
    transports = []
    futures = []

    class Socks4Protocol(asyncio.StreamReaderProtocol):
        def __init__(self, _loop):
            self._loop = _loop
            reader = asyncio.StreamReader(loop=self._loop)
            super().__init__(reader, client_connected_cb=self.negotiate,
                             loop=self._loop)

        def connection_made(self, transport):
            transports.append(transport)
            super().connection_made(transport)

        @asyncio.coroutine
        def negotiate(self, reader, writer):
            writer.write(b'\x00\x5a\x04W\x01\x01\x01\x01')

            data = yield from reader.read(9)

            dst_port = struct.unpack('>H', data[2:4])[0]
            dst_addr = data[4:8]

            if data[-1] != 0x00:
                while True:
                    byte = yield from reader.read(1)
                    if byte == 0x00:
                        break

            if dst_addr == b'\x00\x00\x00\x01':
                dst_addr = bytearray()

                while True:
                    byte = yield from reader.read(1)
                    if byte == 0x00:
                        break
                    dst_addr.append(byte)
            else:
                dst_addr = socket.inet_ntoa(dst_addr)

            cl_reader, cl_writer = yield from asyncio.open_connection(
                host=dst_addr, port=dst_port, loop=self._loop
            )
            transports.append(cl_writer)

            cl_fut = ensure_future(
                self.retranslator(reader, cl_writer), loop=self._loop)
            dst_fut = ensure_future(
                self.retranslator(cl_reader, writer), loop=self._loop)
            futures.append(cl_fut)
            futures.append(dst_fut)

        @asyncio.coroutine
        def retranslator(self, reader, writer):
            data = bytearray()
            while True:
                try:
                    byte = yield from reader.read(1)
                    if not byte:
                        break
                    data.append(byte[0])
                    writer.write(byte)
                    yield from writer.drain()
                except:
                    break

    def run(_fut):
        thread_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(thread_loop)

        srv_coroutine = thread_loop.create_server(
            lambda: Socks4Protocol(thread_loop), '127.0.0.1', port)
        srv = thread_loop.run_until_complete(srv_coroutine)

        waiter = asyncio.Future(loop=thread_loop)
        loop.call_soon_threadsafe(
            _fut.set_result, (thread_loop, waiter))

        try:
            thread_loop.run_until_complete(waiter)
        finally:
            # close opened transports
            for tr in transports:
                tr.close()
            for ft in futures:
                if not ft.done():
                    ft.set_result(1)

            srv.close()
            thread_loop.stop()
            thread_loop.close()
            gc.collect()

    fut = asyncio.Future(loop=loop)
    srv_thread = threading.Thread(target=run, args=(fut,))
    srv_thread.start()

    _thread_loop, _waiter = loop.run_until_complete(fut)

    yield port
    _thread_loop.call_soon_threadsafe(_waiter.set_result, None)
    srv_thread.join()


@contextlib.contextmanager
def http_srv(loop, *, listen_addr=('127.0.0.1', 0), use_ssl=False):
    transports = []

    class TestHttpServer(ServerHttpProtocol):

        def connection_made(self, transport):
            transports.append(transport)
            super().connection_made(transport)

        @asyncio.coroutine
        def handle_request(self, message, payload):
            response = aiohttp.Response(self.writer, 200, message.version)

            text = b'Test message'
            response.add_header('Content-type', 'text/plain')
            response.add_header('Content-length', str(len(text)))
            response.send_headers()
            response.write(text)
            response.write_eof()

    if use_ssl:
        here = os.path.join(os.path.dirname(__file__), '..', 'tests')
        keyfile = os.path.join(here, 'sample.key')
        certfile = os.path.join(here, 'sample.crt')
        sslcontext = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        sslcontext.load_cert_chain(certfile, keyfile)
    else:
        sslcontext = None

    def run(_fut):
        thread_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(thread_loop)

        host, port = listen_addr

        srv_coroutine = thread_loop.create_server(
            lambda: TestHttpServer(), host, port, ssl=sslcontext)
        srv = thread_loop.run_until_complete(srv_coroutine)

        waiter = asyncio.Future(loop=thread_loop)
        loop.call_soon_threadsafe(
            _fut.set_result, (thread_loop, waiter,
                              srv.sockets[0].getsockname()))

        try:
            thread_loop.run_until_complete(waiter)
        finally:
            # close opened transports
            for tr in transports:
                tr.close()

            srv.close()
            thread_loop.stop()
            thread_loop.close()
            gc.collect()

    fut = asyncio.Future(loop=loop)
    srv_thread = threading.Thread(target=run, args=(fut,))
    srv_thread.start()

    _thread_loop, _waiter, _addr = loop.run_until_complete(fut)

    url = '{}://{}:{}'.format(
        'https' if use_ssl else 'http', *_addr)

    yield url
    _thread_loop.call_soon_threadsafe(_waiter.set_result, None)
    srv_thread.join()
