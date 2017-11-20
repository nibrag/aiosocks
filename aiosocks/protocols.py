import asyncio
import socket
import struct
from asyncio import sslproto

from . import constants as c
from .helpers import (
    Socks4Addr, Socks5Addr, Socks5Auth, Socks4Auth
)
from .errors import (
    SocksError, NoAcceptableAuthMethods, LoginAuthenticationFailed,
    InvalidServerReply, InvalidServerVersion
)


DEFAULT_LIMIT = getattr(asyncio.streams, '_DEFAULT_LIMIT', 2**16)


class BaseSocksProtocol(asyncio.StreamReaderProtocol):
    def __init__(self, proxy, proxy_auth, dst, app_protocol_factory, waiter, *,
                 remote_resolve=True, loop=None, ssl=False,
                 server_hostname=None, negotiate_done_cb=None,
                 reader_limit=DEFAULT_LIMIT):
        if not isinstance(dst, (tuple, list)) or len(dst) != 2:
            raise ValueError(
                'Invalid dst format, tuple("dst_host", dst_port))'
            )

        self._proxy = proxy
        self._auth = proxy_auth
        self._dst_host, self._dst_port = dst
        self._remote_resolve = remote_resolve
        self._waiter = waiter
        self._ssl = ssl
        self._server_hostname = server_hostname
        self._negotiate_done_cb = negotiate_done_cb
        self._loop = loop or asyncio.get_event_loop()

        self._transport = None
        self._negotiate_done = False
        self._proxy_peername = None
        self._proxy_sockname = None

        if app_protocol_factory:
            self._app_protocol = app_protocol_factory()
        else:
            self._app_protocol = self

        reader = asyncio.StreamReader(loop=self._loop, limit=reader_limit)

        super().__init__(stream_reader=reader,
                         client_connected_cb=self.negotiate, loop=self._loop)

    async def negotiate(self, reader, writer):
        try:
            req = self.socks_request(c.SOCKS_CMD_CONNECT)
            self._proxy_peername, self._proxy_sockname = await req
        except SocksError as exc:
            exc = SocksError('Can not connect to %s:%s. %s' %
                             (self._dst_host, self._dst_port, exc))
            if not self._waiter.cancelled():
                self._loop.call_soon(self._waiter.set_exception, exc)
        except Exception as exc:
            if not self._waiter.cancelled():
                self._loop.call_soon(self._waiter.set_exception, exc)
        else:
            self._negotiate_done = True

            if self._ssl:
                # Creating a ssl transport needs to be reworked.
                # See details: http://bugs.python.org/issue23749
                self._tls_protocol = sslproto.SSLProtocol(
                    app_protocol=self, sslcontext=self._ssl, server_side=False,
                    server_hostname=self._server_hostname, waiter=self._waiter,
                    loop=self._loop, call_connection_made=False)

                # starttls
                original_transport = self._transport
                self._transport.set_protocol(self._tls_protocol)
                self._transport = self._tls_protocol._app_transport

                self._tls_protocol.connection_made(original_transport)

                self._loop.call_soon(self._app_protocol.connection_made,
                                     self._transport)
            else:
                self._loop.call_soon(self._app_protocol.connection_made,
                                     self._transport)
                self._loop.call_soon(self._waiter.set_result, True)

            if self._negotiate_done_cb is not None:
                res = self._negotiate_done_cb(reader, writer)

                if asyncio.iscoroutine(res):
                    asyncio.Task(res, loop=self._loop)

    def connection_made(self, transport):
        # connection_made is called
        if self._transport:
            return

        super().connection_made(transport)
        self._transport = transport

    def connection_lost(self, exc):
        if self._negotiate_done and self._app_protocol is not self:
            self._loop.call_soon(self._app_protocol.connection_lost, exc)
        super().connection_lost(exc)

    def pause_writing(self):
        if self._negotiate_done and self._app_protocol is not self:
            self._app_protocol.pause_writing()
        else:
            super().pause_writing()

    def resume_writing(self):
        if self._negotiate_done and self._app_protocol is not self:
            self._app_protocol.resume_writing()
        else:
            super().resume_writing()

    def data_received(self, data):
        if self._negotiate_done and self._app_protocol is not self:
            self._app_protocol.data_received(data)
        else:
            super().data_received(data)

    def eof_received(self):
        if self._negotiate_done and self._app_protocol is not self:
            self._app_protocol.eof_received()
        super().eof_received()

    async def socks_request(self, cmd):
        raise NotImplementedError

    def write_request(self, request):
        bdata = bytearray()

        for item in request:
            if isinstance(item, int):
                bdata.append(item)
            elif isinstance(item, (bytearray, bytes)):
                bdata += item
            else:
                raise ValueError('Unsupported item')
        self._stream_writer.write(bdata)

    async def read_response(self, n):
        try:
            return (await self._stream_reader.readexactly(n))
        except asyncio.IncompleteReadError as e:
            raise InvalidServerReply(
                'Server sent fewer bytes than required (%s)' % str(e))

    async def _get_dst_addr(self):
        infos = await self._loop.getaddrinfo(
            self._dst_host, self._dst_port, family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP,
            flags=socket.AI_ADDRCONFIG)
        if not infos:
            raise OSError('getaddrinfo() returned empty list')
        return infos[0][0], infos[0][4][0]

    @property
    def app_protocol(self):
        return self._app_protocol

    @property
    def app_transport(self):
        return self._transport

    @property
    def proxy_sockname(self):
        """
        Returns the bound IP address and port number at the proxy.
        """
        return self._proxy_sockname

    @property
    def proxy_peername(self):
        """
        Returns the IP and port number of the proxy.
        """
        sock = self._transport.get_extra_info('socket')
        return sock.peername if sock else None

    @property
    def peername(self):
        """
        Returns the IP address and port number of the destination
        machine (note: get_proxy_peername returns the proxy)
        """
        return self._proxy_peername

    @property
    def reader(self):
        return self._stream_reader

    @property
    def writer(self):
        return self._stream_writer


class Socks4Protocol(BaseSocksProtocol):
    def __init__(self, proxy, proxy_auth, dst, app_protocol_factory, waiter,
                 remote_resolve=True, loop=None, ssl=False,
                 server_hostname=None, negotiate_done_cb=None,
                 reader_limit=DEFAULT_LIMIT):
        proxy_auth = proxy_auth or Socks4Auth('')

        if not isinstance(proxy, Socks4Addr):
            raise ValueError('Invalid proxy format')

        if not isinstance(proxy_auth, Socks4Auth):
            raise ValueError('Invalid proxy_auth format')

        super().__init__(proxy, proxy_auth, dst, app_protocol_factory,
                         waiter, remote_resolve=remote_resolve, loop=loop,
                         ssl=ssl, server_hostname=server_hostname,
                         reader_limit=reader_limit,
                         negotiate_done_cb=negotiate_done_cb)

    async def socks_request(self, cmd):
        # prepare destination addr/port
        host, port = self._dst_host, self._dst_port
        port_bytes = struct.pack(b'>H', port)
        include_hostname = False

        try:
            host_bytes = socket.inet_aton(host)
        except socket.error:
            if self._remote_resolve:
                host_bytes = bytes([c.NULL, c.NULL, c.NULL, 0x01])
                include_hostname = True
            else:
                # it's not an IP number, so it's probably a DNS name.
                family, host = await self._get_dst_addr()
                host_bytes = socket.inet_aton(host)

        # build and send connect command
        req = [c.SOCKS_VER4, cmd, port_bytes,
               host_bytes, self._auth.login, c.NULL]
        if include_hostname:
            req += [self._dst_host.encode('idna'), c.NULL]

        self.write_request(req)

        # read/process result
        resp = await self.read_response(8)

        if resp[0] != c.NULL:
            raise InvalidServerReply('SOCKS4 proxy server sent invalid data')
        if resp[1] != c.SOCKS4_GRANTED:
            error = c.SOCKS4_ERRORS.get(resp[1], 'Unknown error')
            raise SocksError('[Errno {0:#04x}]: {1}'.format(resp[1], error))

        binded = socket.inet_ntoa(resp[4:]), struct.unpack('>H', resp[2:4])[0]
        return (host, port), binded


class Socks5Protocol(BaseSocksProtocol):
    def __init__(self, proxy, proxy_auth, dst, app_protocol_factory, waiter,
                 remote_resolve=True, loop=None, ssl=False,
                 server_hostname=None, negotiate_done_cb=None,
                 reader_limit=DEFAULT_LIMIT):
        proxy_auth = proxy_auth or Socks5Auth('', '')

        if not isinstance(proxy, Socks5Addr):
            raise ValueError('Invalid proxy format')

        if not isinstance(proxy_auth, Socks5Auth):
            raise ValueError('Invalid proxy_auth format')

        super().__init__(proxy, proxy_auth, dst, app_protocol_factory,
                         waiter, remote_resolve=remote_resolve, loop=loop,
                         ssl=ssl, server_hostname=server_hostname,
                         reader_limit=reader_limit,
                         negotiate_done_cb=negotiate_done_cb)

    async def socks_request(self, cmd):
        await self.authenticate()

        # build and send command
        dst_addr, resolved = await self.build_dst_address(
            self._dst_host, self._dst_port)
        self.write_request([c.SOCKS_VER5, cmd, c.RSV] + dst_addr)

        # read/process command response
        resp = await self.read_response(3)

        if resp[0] != c.SOCKS_VER5:
            raise InvalidServerVersion(
                'SOCKS5 proxy server sent invalid version'
            )
        if resp[1] != c.SOCKS5_GRANTED:
            error = c.SOCKS5_ERRORS.get(resp[1], 'Unknown error')
            raise SocksError('[Errno {0:#04x}]: {1}'.format(resp[1], error))

        binded = await self.read_address()

        return resolved, binded

    async def authenticate(self):
        # send available auth methods
        if self._auth.login and self._auth.password:
            req = [c.SOCKS_VER5, 0x02,
                   c.SOCKS5_AUTH_ANONYMOUS, c.SOCKS5_AUTH_UNAME_PWD]
        else:
            req = [c.SOCKS_VER5, 0x01, c.SOCKS5_AUTH_ANONYMOUS]

        self.write_request(req)

        # read/process response and send auth data if necessary
        chosen_auth = await self.read_response(2)

        if chosen_auth[0] != c.SOCKS_VER5:
            raise InvalidServerVersion(
                'SOCKS5 proxy server sent invalid version'
            )

        if chosen_auth[1] == c.SOCKS5_AUTH_UNAME_PWD:
            req = [0x01, chr(len(self._auth.login)).encode(), self._auth.login,
                   chr(len(self._auth.password)).encode(), self._auth.password]
            self.write_request(req)

            auth_status = await self.read_response(2)
            if auth_status[0] != 0x01:
                raise InvalidServerReply(
                    'SOCKS5 proxy server sent invalid data'
                )
            if auth_status[1] != c.SOCKS5_GRANTED:
                raise LoginAuthenticationFailed(
                    "SOCKS5 authentication failed"
                )
        # offered auth methods rejected
        elif chosen_auth[1] != c.SOCKS5_AUTH_ANONYMOUS:
            if chosen_auth[1] == c.SOCKS5_AUTH_NO_ACCEPTABLE_METHODS:
                raise NoAcceptableAuthMethods(
                    'All offered SOCKS5 authentication methods were rejected'
                )
            else:
                raise InvalidServerReply(
                    'SOCKS5 proxy server sent invalid data'
                )

    async def build_dst_address(self, host, port):
        family_to_byte = {socket.AF_INET: c.SOCKS5_ATYP_IPv4,
                          socket.AF_INET6: c.SOCKS5_ATYP_IPv6}
        port_bytes = struct.pack('>H', port)

        # if the given destination address is an IP address, we will
        # use the IP address request even if remote resolving was specified.
        for family in (socket.AF_INET, socket.AF_INET6):
            try:
                host_bytes = socket.inet_pton(family, host)
                req = [family_to_byte[family], host_bytes, port_bytes]
                return req, (host, port)
            except socket.error:
                pass

        # it's not an IP number, so it's probably a DNS name.
        if self._remote_resolve:
            host_bytes = host.encode('idna')
            req = [c.SOCKS5_ATYP_DOMAIN, chr(len(host_bytes)).encode(),
                   host_bytes, port_bytes]
        else:
            family, host_bytes = await self._get_dst_addr()
            host_bytes = socket.inet_pton(family, host_bytes)
            req = [family_to_byte[family], host_bytes, port_bytes]
            host = socket.inet_ntop(family, host_bytes)

        return req, (host, port)

    async def read_address(self):
        atype = await self.read_response(1)

        if atype[0] == c.SOCKS5_ATYP_IPv4:
            addr = socket.inet_ntoa((await self.read_response(4)))
        elif atype[0] == c.SOCKS5_ATYP_DOMAIN:
            length = await self.read_response(1)
            addr = await self.read_response(ord(length))
        elif atype[0] == c.SOCKS5_ATYP_IPv6:
            addr = await self.read_response(16)
            addr = socket.inet_ntop(socket.AF_INET6, addr)
        else:
            raise InvalidServerReply('SOCKS5 proxy server sent invalid data')

        port = await self.read_response(2)
        port = struct.unpack('>H', port)[0]

        return addr, port
