import pytest
import aiosocks
import aiohttp
import os
import ssl
from aiohttp import web
from aiohttp.test_utils import RawTestServer
from aiosocks.test_utils import FakeSocksSrv, FakeSocks4Srv
from aiosocks.connector import ProxyConnector, ProxyClientRequest


async def test_socks4_connect_success(loop):
    pld = b'\x00\x5a\x04W\x01\x01\x01\x01test'

    async with FakeSocksSrv(loop, pld) as srv:
        addr = aiosocks.Socks4Addr('127.0.0.1', srv.port)
        auth = aiosocks.Socks4Auth('usr')
        dst = ('python.org', 80)

        transport, protocol = await aiosocks.create_connection(
            None, addr, auth, dst, loop=loop)

        assert protocol.proxy_sockname == ('1.1.1.1', 1111)

        data = await protocol._stream_reader.read(4)
        assert data == b'test'

        transport.close()


async def test_socks4_invalid_data(loop):
    pld = b'\x01\x5a\x04W\x01\x01\x01\x01'

    async with FakeSocksSrv(loop, pld) as srv:
        addr = aiosocks.Socks4Addr('127.0.0.1', srv.port)
        auth = aiosocks.Socks4Auth('usr')
        dst = ('python.org', 80)

        with pytest.raises(aiosocks.SocksError) as ct:
            await aiosocks.create_connection(
                None, addr, auth, dst, loop=loop)
        assert 'invalid data' in str(ct.value)


async def test_socks4_srv_error(loop):
    pld = b'\x00\x5b\x04W\x01\x01\x01\x01'

    async with FakeSocksSrv(loop, pld) as srv:
        addr = aiosocks.Socks4Addr('127.0.0.1', srv.port)
        auth = aiosocks.Socks4Auth('usr')
        dst = ('python.org', 80)

        with pytest.raises(aiosocks.SocksError) as ct:
            await aiosocks.create_connection(
                None, addr, auth, dst, loop=loop)
        assert '0x5b' in str(ct.value)


async def test_socks5_connect_success_anonymous(loop):
    pld = b'\x05\x00\x05\x00\x00\x01\x01\x01\x01\x01\x04Wtest'

    async with FakeSocksSrv(loop, pld) as srv:
        addr = aiosocks.Socks5Addr('127.0.0.1', srv.port)
        auth = aiosocks.Socks5Auth('usr', 'pwd')
        dst = ('python.org', 80)

        transport, protocol = await aiosocks.create_connection(
            None, addr, auth, dst, loop=loop)

        assert protocol.proxy_sockname == ('1.1.1.1', 1111)

        data = await protocol._stream_reader.read(4)
        assert data == b'test'

        transport.close()


async def test_socks5_connect_success_usr_pwd(loop):
    pld = b'\x05\x02\x01\x00\x05\x00\x00\x01\x01\x01\x01\x01\x04Wtest'

    async with FakeSocksSrv(loop, pld) as srv:
        addr = aiosocks.Socks5Addr('127.0.0.1', srv.port)
        auth = aiosocks.Socks5Auth('usr', 'pwd')
        dst = ('python.org', 80)

        transport, protocol = await aiosocks.create_connection(
            None, addr, auth, dst, loop=loop)
        assert protocol.proxy_sockname == ('1.1.1.1', 1111)

        data = await protocol._stream_reader.read(4)
        assert data == b'test'
        transport.close()


async def test_socks5_auth_ver_err(loop):
    async with FakeSocksSrv(loop, b'\x04\x02') as srv:
        addr = aiosocks.Socks5Addr('127.0.0.1', srv.port)
        auth = aiosocks.Socks5Auth('usr', 'pwd')
        dst = ('python.org', 80)

        with pytest.raises(aiosocks.SocksError) as ct:
            await aiosocks.create_connection(
                None, addr, auth, dst, loop=loop)
        assert 'invalid version' in str(ct.value)


async def test_socks5_auth_method_rejected(loop):
    async with FakeSocksSrv(loop, b'\x05\xFF') as srv:
        addr = aiosocks.Socks5Addr('127.0.0.1', srv.port)
        auth = aiosocks.Socks5Auth('usr', 'pwd')
        dst = ('python.org', 80)

        with pytest.raises(aiosocks.SocksError) as ct:
            await aiosocks.create_connection(
                None, addr, auth, dst, loop=loop)
        assert 'authentication methods were rejected' in str(ct.value)


async def test_socks5_auth_status_invalid(loop):
    async with FakeSocksSrv(loop, b'\x05\xF0') as srv:
        addr = aiosocks.Socks5Addr('127.0.0.1', srv.port)
        auth = aiosocks.Socks5Auth('usr', 'pwd')
        dst = ('python.org', 80)

        with pytest.raises(aiosocks.SocksError) as ct:
            await aiosocks.create_connection(
                None, addr, auth, dst, loop=loop)
        assert 'invalid data' in str(ct.value)


async def test_socks5_auth_status_invalid2(loop):
    async with FakeSocksSrv(loop, b'\x05\x02\x02\x00') as srv:
        addr = aiosocks.Socks5Addr('127.0.0.1', srv.port)
        auth = aiosocks.Socks5Auth('usr', 'pwd')
        dst = ('python.org', 80)

        with pytest.raises(aiosocks.SocksError) as ct:
            await aiosocks.create_connection(
                None, addr, auth, dst, loop=loop)
        assert 'invalid data' in str(ct.value)


async def test_socks5_auth_failed(loop):
    async with FakeSocksSrv(loop, b'\x05\x02\x01\x01') as srv:
        addr = aiosocks.Socks5Addr('127.0.0.1', srv.port)
        auth = aiosocks.Socks5Auth('usr', 'pwd')
        dst = ('python.org', 80)

        with pytest.raises(aiosocks.SocksError) as ct:
            await aiosocks.create_connection(
                None, addr, auth, dst, loop=loop)
        assert 'authentication failed' in str(ct.value)


async def test_socks5_cmd_ver_err(loop):
    async with FakeSocksSrv(loop, b'\x05\x02\x01\x00\x04\x00\x00') as srv:
        addr = aiosocks.Socks5Addr('127.0.0.1', srv.port)
        auth = aiosocks.Socks5Auth('usr', 'pwd')
        dst = ('python.org', 80)

        with pytest.raises(aiosocks.SocksError) as ct:
            await aiosocks.create_connection(
                None, addr, auth, dst, loop=loop)
        assert 'invalid version' in str(ct.value)


async def test_socks5_cmd_not_granted(loop):
    async with FakeSocksSrv(loop, b'\x05\x02\x01\x00\x05\x01\x00') as srv:
        addr = aiosocks.Socks5Addr('127.0.0.1', srv.port)
        auth = aiosocks.Socks5Auth('usr', 'pwd')
        dst = ('python.org', 80)

        with pytest.raises(aiosocks.SocksError) as ct:
            await aiosocks.create_connection(
                None, addr, auth, dst, loop=loop)
        assert 'General SOCKS server failure' in str(ct.value)


async def test_socks5_invalid_address_type(loop):
    async with FakeSocksSrv(loop, b'\x05\x02\x01\x00\x05\x00\x00\xFF') as srv:
        addr = aiosocks.Socks5Addr('127.0.0.1', srv.port)
        auth = aiosocks.Socks5Auth('usr', 'pwd')
        dst = ('python.org', 80)

        with pytest.raises(aiosocks.SocksError) as ct:
            await aiosocks.create_connection(
                None, addr, auth, dst, loop=loop)
        assert 'invalid data' in str(ct.value)


async def test_socks5_atype_ipv4(loop):
    pld = b'\x05\x02\x01\x00\x05\x00\x00\x01\x01\x01\x01\x01\x04W'

    async with FakeSocksSrv(loop, pld) as srv:
        addr = aiosocks.Socks5Addr('127.0.0.1', srv.port)
        auth = aiosocks.Socks5Auth('usr', 'pwd')
        dst = ('python.org', 80)

        transport, protocol = await aiosocks.create_connection(
            None, addr, auth, dst, loop=loop)
        assert protocol.proxy_sockname == ('1.1.1.1', 1111)

        transport.close()


async def test_socks5_atype_ipv6(loop):
    pld = b'\x05\x02\x01\x00\x05\x00\x00\x04\x00\x00\x00\x00' \
          b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x11\x04W'

    async with FakeSocksSrv(loop, pld) as srv:
        addr = aiosocks.Socks5Addr('127.0.0.1', srv.port)
        auth = aiosocks.Socks5Auth('usr', 'pwd')
        dst = ('python.org', 80)

        transport, protocol = await aiosocks.create_connection(
            None, addr, auth, dst, loop=loop)
        assert protocol.proxy_sockname == ('::111', 1111)

        transport.close()


async def test_socks5_atype_domain(loop):
    pld = b'\x05\x02\x01\x00\x05\x00\x00\x03\x0apython.org\x04W'

    async with FakeSocksSrv(loop, pld) as srv:
        addr = aiosocks.Socks5Addr('127.0.0.1', srv.port)
        auth = aiosocks.Socks5Auth('usr', 'pwd')
        dst = ('python.org', 80)

        transport, protocol = await aiosocks.create_connection(
            None, addr, auth, dst, loop=loop)
        assert protocol.proxy_sockname == (b'python.org', 1111)

        transport.close()


async def test_http_connect(loop):
    async def handler(request):
        return web.Response(text='Test message')

    async with RawTestServer(handler, host='127.0.0.1', loop=loop) as ws:
        async with FakeSocks4Srv(loop) as srv:
            conn = ProxyConnector(loop=loop, remote_resolve=False)

            async with aiohttp.ClientSession(
                    connector=conn, loop=loop,
                    request_class=ProxyClientRequest) as ses:
                proxy = 'socks4://127.0.0.1:{}'.format(srv.port)

                async with ses.get(ws.make_url('/'), proxy=proxy) as resp:
                    assert resp.status == 200
                    assert (await resp.text()) == 'Test message'


async def test_https_connect(loop):
    async def handler(request):
        return web.Response(text='Test message')

    here = os.path.join(os.path.dirname(__file__), '..', 'tests')
    keyfile = os.path.join(here, 'sample.key')
    certfile = os.path.join(here, 'sample.crt')
    sslcontext = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    sslcontext.load_cert_chain(certfile, keyfile)

    ws = RawTestServer(handler, scheme='https', host='127.0.0.1', loop=loop)
    await ws.start_server(loop=loop, ssl=sslcontext)

    v_fp = (b'0\x9a\xc9D\x83\xdc\x91\'\x88\x91\x11\xa1d\x97\xfd'
            b'\xcb~7U\x14D@L'
            b'\x11\xab\x99\xa8\xae\xb7\x14\xee\x8b')
    inv_fp = (b'0\x9d\xc9D\x83\xdc\x91\'\x88\x91\x11\xa1d\x97\xfd'
              b'\xcb~7U\x14D@L'
              b'\x11\xab\x99\xa8\xae\xb7\x14\xee\x9e')

    async with FakeSocks4Srv(loop) as srv:
        v_conn = ProxyConnector(loop=loop, remote_resolve=False,
                                fingerprint=v_fp)
        inv_conn = ProxyConnector(loop=loop, remote_resolve=False,
                                  fingerprint=inv_fp)

        async with aiohttp.ClientSession(
                connector=v_conn, loop=loop,
                request_class=ProxyClientRequest) as ses:
            proxy = 'socks4://127.0.0.1:{}'.format(srv.port)

            async with ses.get(ws.make_url('/'), proxy=proxy) as resp:
                assert resp.status == 200
                assert (await resp.text()) == 'Test message'

        async with aiohttp.ClientSession(
                connector=inv_conn, loop=loop,
                request_class=ProxyClientRequest) as ses:
            proxy = 'socks4://127.0.0.1:{}'.format(srv.port)

            with pytest.raises(aiohttp.ServerFingerprintMismatch):
                async with ses.get(ws.make_url('/'), proxy=proxy) as resp:
                    assert resp.status == 200
