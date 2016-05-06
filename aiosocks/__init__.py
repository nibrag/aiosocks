import asyncio
from .errors import *
from .helpers import *
from .protocols import Socks4Protocol, Socks5Protocol

__version__ = '0.1a'

__all__ = ('Socks4Protocol', 'Socks5Protocol', 'Socks4Auth',
           'Socks5Auth', 'Socks4Server', 'Socks5Server', 'SocksError',
           'NoAcceptableAuthMethods', 'LoginAuthenticationFailed',
           'InvalidServerVersion', 'InvalidServerReply', 'create_connection')


async def create_connection(protocol_factory, proxy, proxy_auth, dst, *, remote_resolve=True,
                            loop=None, ssl=None, family=0, proto=0, flags=0, sock=None,
                            local_addr=None, server_hostname=None):

    assert isinstance(proxy, SocksServer), (
        'proxy must be Socks4Server() or Socks5Server() tuple'
    )

    assert proxy_auth is None or isinstance(proxy_auth, (Socks4Auth, Socks5Auth)), (
        'proxy_auth must be None or Socks4Auth() or Socks5Auth() tuple', proxy_auth
    )
    assert isinstance(dst, (tuple, list)) and len(dst) == 2, (
        'invalid dst format, tuple("dst_host", dst_port))'
    )

    if (isinstance(proxy, Socks4Server) and not
            (proxy_auth is None or isinstance(proxy_auth, Socks4Auth))):
        raise ValueError("proxy is Socks4Server but proxy_auth is not Socks4Auth")

    if (isinstance(proxy, Socks5Server) and not
            (proxy_auth is None or isinstance(proxy_auth, Socks5Auth))):
        raise ValueError("proxy is Socks5Server but proxy_auth is not Socks5Auth")

    loop = loop or asyncio.get_event_loop()

    def socks_factory():
        if isinstance(proxy, Socks4Server):
            socks_proto = Socks4Protocol
        else:
            socks_proto = Socks5Protocol

        return socks_proto(
            proxy=proxy, proxy_auth=proxy_auth, dst=dst,
            remote_resolve=remote_resolve, loop=loop)

    transport, protocol = await loop.create_connection(
        socks_factory, proxy.host, proxy.port, ssl=ssl, family=family, proto=proto,
        flags=flags, sock=sock, local_addr=local_addr, server_hostname=server_hostname)

    await protocol.negotiate_done()

    sock = transport.get_extra_info('socket')

    return await loop._create_connection_transport(
        sock, protocol_factory, ssl, server_hostname)
