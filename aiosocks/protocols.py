import asyncio
import socket
import struct
from . import constants as c
from .helpers import (
    Socks4Addr, Socks5Addr, Socks5Auth, Socks4Auth
)
from .errors import *


class SocksProtocol(asyncio.StreamReaderProtocol):
    def __init__(self, proxy, proxy_auth, dst, remote_resolve=True, loop=None):
        if not isinstance(dst, (tuple, list)) or len(dst) != 2:
            raise ValueError('Invalid dst format, tuple("dst_host", dst_port))')

        self._proxy = proxy
        self._auth = proxy_auth
        self._dst_host, self._dst_port = dst
        self._remote_resolve = remote_resolve

        self._loop = loop or asyncio.get_event_loop()
        self._transport = None

        self._negotiate_done = None

        reader = asyncio.StreamReader(loop=self._loop)

        super().__init__(stream_reader=reader, loop=self._loop)

    def connection_made(self, transport):
        super().connection_made(transport)
        self._transport = transport

        req_coro = self.socks_request(c.SOCKS_CMD_CONNECT)
        self._negotiate_done = asyncio.ensure_future(req_coro, loop=self._loop)

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

        self._transport.write(bdata)

    async def read_response(self, n):
        return await self._stream_reader.read(n)

    async def _get_dst_addr(self):
        infos = await self._loop.getaddrinfo(self._dst_host, self._dst_port,
                                             family=socket.AF_UNSPEC, type=socket.SOCK_STREAM,
                                             proto=socket.IPPROTO_TCP, flags=socket.AI_ADDRCONFIG)
        if not infos:
            raise OSError('getaddrinfo() returned empty list')
        return infos[0][0], infos[0][4][0]

    async def negotiate_done(self):
        return await self._negotiate_done


class Socks4Protocol(SocksProtocol):
    def __init__(self, proxy, proxy_auth, dst, remote_resolve=True, loop=None):
        if not isinstance(proxy, Socks4Addr):
            raise ValueError('Invalid proxy format')

        if proxy_auth is not None and not isinstance(proxy_auth, Socks4Auth):
            raise ValueError('Invalid proxy_auth format')

        super().__init__(proxy, proxy_auth, dst, remote_resolve, loop)

        if proxy_auth is None:
            self._auth = Socks4Auth('')

    async def socks_request(self, cmd):
        # prepare destination addr/port
        host, port = self._dst_host, self._dst_port
        port_bytes = struct.pack(b'>H', port)
        try:
            host_bytes = socket.inet_aton(host)
        except socket.error:
            if self._remote_resolve:
                host_bytes = bytes([c.NULL, c.NULL, c.NULL, 0x01])
            else:
                # it's not an IP number, so it's probably a DNS name.
                family, host = await self._get_dst_addr()
                host_bytes = socket.inet_aton(host)

        # build and send connect command
        req = [c.SOCKS_VER4, cmd, port_bytes, host_bytes, self._auth.login, c.NULL]
        if self._remote_resolve:
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


class Socks5Protocol(SocksProtocol):
    def __init__(self, proxy, proxy_auth, dst, remote_resolve=True, loop=None):
        if not isinstance(proxy, Socks5Addr):
            raise ValueError('Invalid proxy format')

        if proxy_auth is not None and not isinstance(proxy_auth, Socks5Auth):
            raise ValueError('Invalid proxy_auth format')

        super().__init__(proxy, proxy_auth, dst, remote_resolve, loop)

        if proxy_auth is None:
            self._auth = Socks5Auth('', '')

    async def socks_request(self, cmd):
        # send available auth methods
        if self._auth.login and self._auth.password:
            req = [c.SOCKS_VER5, 0x02, c.SOCKS5_AUTH_ANONYMOUS, c.SOCKS5_AUTH_UNAME_PWD]
        else:
            req = [c.SOCKS_VER5, 0x01, c.SOCKS5_AUTH_ANONYMOUS]

        self.write_request(req)

        # read/process response and send auth data if necessary
        chosen_auth = await self.read_response(2)

        if chosen_auth[0] != c.SOCKS_VER5:
            raise InvalidServerVersion('SOCKS5 proxy server sent invalid version')

        if chosen_auth[1] == c.SOCKS5_AUTH_UNAME_PWD:
            req = [0x01, chr(len(self._auth.login)).encode(), self._auth.login,
                   chr(len(self._auth.password)).encode(), self._auth.password]
            self.write_request(req)

            auth_status = await self.read_response(2)
            if auth_status[0] != 0x01:
                raise InvalidServerReply('SOCKS5 proxy server sent invalid data')
            if auth_status[1] != c.SOCKS5_GRANTED:
                raise LoginAuthenticationFailed('SOCKS5 authentication failed')
        # offered auth methods rejected
        elif chosen_auth[1] != c.SOCKS5_AUTH_ANONYMOUS:
            if chosen_auth[1] == c.SOCKS5_AUTH_NO_ACCEPTABLE_METHODS:
                raise NoAcceptableAuthMethods('All offered SOCKS5 authentication methods were rejected')
            else:
                raise InvalidServerReply('SOCKS5 proxy server sent invalid data')

        # build and send command
        self.write_request([c.SOCKS_VER5, cmd, c.RSV])
        resolved = await self.write_address(self._dst_host, self._dst_port)

        # read/process command response
        resp = await self.read_response(3)

        if resp[0] != c.SOCKS_VER5:
            raise InvalidServerVersion('SOCKS5 proxy server sent invalid version')
        if resp[1] != c.SOCKS5_GRANTED:
            error = c.SOCKS5_ERRORS.get(resp[1], 'Unknown error')
            raise SocksError('[Errno {0:#04x}]: {1}'.format(resp[1], error))

        binded = await self.read_address()

        return resolved, binded

    async def write_address(self, host, port):
        family_to_byte = {socket.AF_INET: c.SOCKS5_ATYP_IPv4, socket.AF_INET6: c.SOCKS5_ATYP_IPv6}
        port_bytes = struct.pack('>H', port)

        # if the given destination address is an IP address, we will
        # use the IP address request even if remote resolving was specified.
        for family in (socket.AF_INET, socket.AF_INET6):
            try:
                host_bytes = socket.inet_pton(family, host)
                req = [family_to_byte[family], host_bytes, port_bytes]
                self.write_request(req)
                return host, port
            except socket.error:
                pass

        # it's not an IP number, so it's probably a DNS name.
        if self._remote_resolve:
            host_bytes = host.encode('idna')
            req = [c.SOCKS5_ATYP_DOMAIN, chr(len(host_bytes)).encode(), host_bytes, port_bytes]
        else:
            family, host_bytes = await self._get_dst_addr()
            host_bytes = socket.inet_pton(family, host_bytes)
            req = [family_to_byte[family], host_bytes, port_bytes]
            host = socket.inet_ntop(family, host_bytes)

        self.write_request(req)
        return host, port

    async def read_address(self):
        atype = await self.read_response(1)

        if atype[0] == c.SOCKS5_ATYP_IPv4:
            addr = socket.inet_ntoa(await self.read_response(4))
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
