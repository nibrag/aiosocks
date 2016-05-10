import socket

import aiohttp
import ipaddress
from aiohttp.errors import ProxyConnectionError
from .errors import SocksError, SocksConnectionError
from . import create_connection

__all__ = ('SocksConnector',)


class SocksConnector(aiohttp.TCPConnector):
    def __init__(self, proxy, proxy_auth=None, *, remote_resolve=True, **kwgs):
        super().__init__(**kwgs)

        self._proxy = proxy
        self._proxy_auth = proxy_auth
        self._remote_resolve = remote_resolve

    @property
    def proxy(self):
        """Proxy info.
        Should be Socks4Server/Socks5Server instance.
        """
        return self._proxy

    @property
    def proxy_auth(self):
        """Proxy auth info.
        Should be Socks4Auth/Socks5Auth instance.
        """
        return self._proxy_auth

    async def _create_connection(self, req):
        if not self._remote_resolve:
            dst_hosts = await self._resolve_host(req.host, req.port)
            dst = dst_hosts[0]['host'], dst_hosts[0]['port']
        else:
            dst = req.host, req.port
        exc = None

        # if self._resolver is AsyncResolver and self._proxy.host
        # is ip address, then aiodns raise DNSError.
        # It's aiohttp bug? Hot fix:
        try:
            ipaddress.ip_address(self._proxy.host)
            proxy_hosts = await self._loop.getaddrinfo(self._proxy.host,
                                                       self._proxy.port)
            family, _, proto, _, address = proxy_hosts[0]

            proxy_hosts = ({'hostname': self._proxy.host,
                            'host': address[0], 'port': address[1],
                            'family': family, 'proto': proto,
                            'flags': socket.AI_NUMERICHOST},)
        except ValueError:
            proxy_hosts = await self._resolve_host(self._proxy.host,
                                                   self._proxy.port)

        for hinfo in proxy_hosts:
            try:
                proxy = self._proxy.__class__(host=hinfo['host'],
                                              port=hinfo['port'])

                transp, proto = await create_connection(
                    self._factory, proxy, self._proxy_auth, dst,
                    loop=self._loop, remote_resolve=self._remote_resolve,
                    ssl=None, family=hinfo['family'], proto=hinfo['proto'],
                    flags=hinfo['flags'], local_addr=self._local_addr)

                return transp, proto
            except (OSError, SocksError, SocksConnectionError) as e:
                exc = e
        else:
            if isinstance(exc, SocksConnectionError):
                raise ProxyConnectionError(*exc.args)
            if isinstance(exc, SocksError):
                raise exc
            else:
                raise aiohttp.ClientOSError(
                    exc.errno, 'Can not connect to %s:%s [%s]' %
                    (req.host, req.port, exc.strerror)) from exc
