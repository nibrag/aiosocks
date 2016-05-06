import aiohttp
from . import create_connection

__all__ = ('SocksConnector',)


class SocksConnector(aiohttp.TCPConnector):
    def __init__(self, proxy, proxy_auth=None, *, remote_resolve=True, **kwargs):
        super().__init__(**kwargs)

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

        proxy_hosts = await self._resolve_host(self._proxy.host, self._proxy.port)

        for hinfo in proxy_hosts:
            try:
                proxy = self._proxy.__class__(host=hinfo['host'], port=hinfo['port'])

                transp, proto = await create_connection(
                    self._factory, proxy, self._proxy_auth, dst,
                    remote_resolve=self._remote_resolve, ssl=None, family=hinfo['family'],
                    proto=hinfo['proto'], flags=hinfo['flags'], local_addr=self._local_addr)

                return transp, proto
            except OSError as e:
                exc = e
        else:
            raise aiohttp.ClientOSError(exc.errno,
                                        'Can not connect to %s:%s [%s]' %
                                        (req.host, req.port, exc.strerror)) from exc
