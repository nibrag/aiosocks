import asyncio
import contextlib
import socket
from unittest import mock
import gc
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
