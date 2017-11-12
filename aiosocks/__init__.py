import asyncio
from .errors import (
    SocksError, NoAcceptableAuthMethods, LoginAuthenticationFailed,
    SocksConnectionError, InvalidServerReply, InvalidServerVersion
)
from .helpers import (
    SocksAddr, Socks4Addr, Socks5Addr, Socks4Auth, Socks5Auth
)
from .protocols import Socks4Protocol, Socks5Protocol, DEFAULT_LIMIT

__version__ = '0.2.5'

__all__ = ('Socks4Protocol', 'Socks5Protocol', 'Socks4Auth',
           'Socks5Auth', 'Socks4Addr', 'Socks5Addr', 'SocksError',
           'NoAcceptableAuthMethods', 'LoginAuthenticationFailed',
           'SocksConnectionError', 'InvalidServerVersion',
           'InvalidServerReply', 'create_connection', 'open_connection')


async def create_connection(protocol_factory, proxy, proxy_auth, dst, *,
                            remote_resolve=True, loop=None, ssl=None, family=0,
                            proto=0, flags=0, sock=None, local_addr=None,
                            server_hostname=None, reader_limit=DEFAULT_LIMIT):
    assert isinstance(proxy, SocksAddr), (
        'proxy must be Socks4Addr() or Socks5Addr() tuple'
    )

    assert proxy_auth is None or isinstance(proxy_auth,
                                            (Socks4Auth, Socks5Auth)), (
        'proxy_auth must be None or Socks4Auth() '
        'or Socks5Auth() tuple', proxy_auth
    )
    assert isinstance(dst, (tuple, list)) and len(dst) == 2, (
        'invalid dst format, tuple("dst_host", dst_port))'
    )

    if (isinstance(proxy, Socks4Addr) and not
            (proxy_auth is None or isinstance(proxy_auth, Socks4Auth))):
        raise ValueError(
            "proxy is Socks4Addr but proxy_auth is not Socks4Auth"
        )

    if (isinstance(proxy, Socks5Addr) and not
            (proxy_auth is None or isinstance(proxy_auth, Socks5Auth))):
        raise ValueError(
            "proxy is Socks5Addr but proxy_auth is not Socks5Auth"
        )

    if server_hostname is not None and not ssl:
        raise ValueError('server_hostname is only meaningful with ssl')

    if server_hostname is None and ssl:
        # read details: asyncio.create_connection
        server_hostname = dst[0]

    loop = loop or asyncio.get_event_loop()
    waiter = asyncio.Future(loop=loop)

    def socks_factory():
        if isinstance(proxy, Socks4Addr):
            socks_proto = Socks4Protocol
        else:
            socks_proto = Socks5Protocol

        return socks_proto(proxy=proxy, proxy_auth=proxy_auth, dst=dst,
                           app_protocol_factory=protocol_factory,
                           waiter=waiter, remote_resolve=remote_resolve,
                           loop=loop, ssl=ssl, server_hostname=server_hostname,
                           reader_limit=reader_limit)

    try:
        transport, protocol = await loop.create_connection(
            socks_factory, proxy.host, proxy.port, family=family,
            proto=proto, flags=flags, sock=sock, local_addr=local_addr)
    except OSError as exc:
        raise SocksConnectionError(
            '[Errno %s] Can not connect to proxy %s:%d [%s]' %
            (exc.errno, proxy.host, proxy.port, exc.strerror)) from exc

    try:
        await waiter
    except:  # noqa
        transport.close()
        raise

    return protocol.app_transport, protocol.app_protocol


async def open_connection(proxy, proxy_auth, dst, *, remote_resolve=True,
                          loop=None, limit=DEFAULT_LIMIT, **kwds):
    _, protocol = await create_connection(
        None, proxy, proxy_auth, dst, reader_limit=limit,
        remote_resolve=remote_resolve, loop=loop, **kwds)

    return protocol.reader, protocol.writer
