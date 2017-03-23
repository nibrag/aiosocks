try:
    import aiohttp
    from aiohttp.client_exceptions import ClientProxyConnectionError
    from aiohttp.helpers import BasicAuth as HttpProxyAuth
except ImportError:
    raise ImportError('aiosocks.SocksConnector require aiohttp library')

import asyncio
from collections import namedtuple
from .errors import SocksError, SocksConnectionError
from .helpers import SocksAddr
from . import create_connection

__all__ = ('SocksConnector', 'HttpProxyAddr', 'HttpProxyAuth')


class HttpProxyAddr(namedtuple('HttpProxyAddr', ['url'])):
    def __new__(cls, url):
        if url is None:
            raise ValueError('None is not allowed as url value')
        return super().__new__(cls, url)


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

    def _validate_ssl_fingerprint(self, transport, host):
        has_cert = transport.get_extra_info('sslcontext')
        if has_cert and self._fingerprint:
            sock = transport.get_extra_info('socket')
            if not hasattr(sock, 'getpeercert'):
                # Workaround for asyncio 3.5.0
                # Starting from 3.5.1 version
                # there is 'ssl_object' extra info in transport
                sock = transport._ssl_protocol._sslpipe.ssl_object
            # gives DER-encoded cert as a sequence of bytes (or None)
            cert = sock.getpeercert(binary_form=True)
            assert cert
            got = self._hashfunc(cert).digest()
            expected = self._fingerprint
            if got != expected:
                transport.close()
                raise aiohttp.FingerprintMismatch(
                    expected, got, host, 80
                )

    @asyncio.coroutine
    def _create_connection(self, req):
        if req.ssl:
            sslcontext = self.ssl_context
        else:
            sslcontext = None

        if not self._remote_resolve:
            dst_hosts = yield from self._resolve_host(req.host, req.port)
            dst = dst_hosts[0]['host'], dst_hosts[0]['port']
        else:
            dst = req.host, req.port

        proxy_hosts = yield from self._resolve_host(self._proxy.host,
                                                    self._proxy.port)
        exc = None

        for hinfo in proxy_hosts:
            try:
                proxy = self._proxy.__class__(host=hinfo['host'],
                                              port=hinfo['port'])

                transp, proto = yield from create_connection(
                    self._factory, proxy, self._proxy_auth, dst,
                    loop=self._loop, remote_resolve=self._remote_resolve,
                    ssl=sslcontext, family=hinfo['family'],
                    proto=hinfo['proto'], flags=hinfo['flags'],
                    local_addr=self._local_addr,
                    server_hostname=req.host if sslcontext else None)
                self._validate_ssl_fingerprint(transp, req.host)

                return transp, proto
            except (OSError, SocksError, SocksConnectionError) as e:
                exc = e
        else:
            if isinstance(exc, SocksConnectionError):
                raise ClientProxyConnectionError(*exc.args)
            if isinstance(exc, SocksError):
                raise exc
            else:
                raise aiohttp.ClientOSError(
                    exc.errno, 'Can not connect to %s:%s [%s]' %
                               (req.host, req.port, exc.strerror)) from exc


def proxy_connector(proxy, proxy_auth=None, **kwargs):
    if isinstance(proxy, HttpProxyAddr):
        return aiohttp.ProxyConnector(
            proxy.url, proxy_auth=proxy_auth, **kwargs)
    elif isinstance(proxy, SocksAddr):
        return SocksConnector(proxy, proxy_auth, **kwargs)
    else:
        raise ValueError('Unsupported `proxy` format')
