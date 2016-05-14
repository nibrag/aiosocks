import asyncio
import socket
from unittest import mock
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


class SocksPrimitiveProtocol(asyncio.Protocol):
    def __init__(self, write_buff):
        self._write_buff = write_buff
        self._transport = None

    def connection_made(self, transport):
        self._transport = transport

    def data_received(self, data):
        self._transport.write(self._write_buff)

    def connection_lost(self, exc):
        self._transport.close()


@asyncio.coroutine
def fake_socks_srv(loop, write_buff):
    port = find_unused_port()

    def factory():
        return SocksPrimitiveProtocol(write_buff)

    server = yield from loop.create_server(factory, '127.0.0.1', port)
    return server, port

