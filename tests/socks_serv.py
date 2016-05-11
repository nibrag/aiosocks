import asyncio
import socket
import functools


def find_unused_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port


@asyncio.coroutine
def socks_handler(reader, writer, write_buff):
    writer.write(write_buff)


@asyncio.coroutine
def fake_socks_srv(loop, write_buff):
    port = find_unused_port()
    handler = functools.partial(socks_handler, write_buff=write_buff)
    srv = yield from asyncio.start_server(
        handler, '127.0.0.1', port, family=socket.AF_INET, loop=loop)
    return srv, port
