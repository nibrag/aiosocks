import aiosocks
import asyncio
import aiohttp
import unittest
from aiosocks.connector import SocksConnector

try:
    from asyncio import ensure_future
except ImportError:
    ensure_future = asyncio.async

from .helpers import fake_socks_srv, fake_socks4_srv, http_srv


class TestCreateSocks4Connection(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)

    def tearDown(self):
        self.loop.close()

    def test_connect_success(self):
        with fake_socks_srv(self.loop,
                            b'\x00\x5a\x04W\x01\x01\x01\x01test') as port:
            addr = aiosocks.Socks4Addr('127.0.0.1', port)
            auth = aiosocks.Socks4Auth('usr')
            dst = ('python.org', 80)

            coro = aiosocks.create_connection(
                None, addr, auth, dst, loop=self.loop)
            transport, protocol = self.loop.run_until_complete(coro)

            self.assertEqual(protocol.proxy_sockname, ('1.1.1.1', 1111))

            data = self.loop.run_until_complete(
                protocol._stream_reader.read(4))
            self.assertEqual(data, b'test')

            transport.close()

    def test_invalid_data(self):
        with fake_socks_srv(self.loop,
                            b'\x01\x5a\x04W\x01\x01\x01\x01') as port:
            addr = aiosocks.Socks4Addr('127.0.0.1', port)
            auth = aiosocks.Socks4Auth('usr')
            dst = ('python.org', 80)

            with self.assertRaises(aiosocks.SocksError) as ct:
                coro = aiosocks.create_connection(
                    None, addr, auth, dst, loop=self.loop)
                self.loop.run_until_complete(coro)
            self.assertIn('invalid data', str(ct.exception))

    def test_socks_srv_error(self):
        with fake_socks_srv(self.loop,
                            b'\x00\x5b\x04W\x01\x01\x01\x01') as port:
            addr = aiosocks.Socks4Addr('127.0.0.1', port)
            auth = aiosocks.Socks4Auth('usr')
            dst = ('python.org', 80)

            with self.assertRaises(aiosocks.SocksError) as ct:
                coro = aiosocks.create_connection(
                    None, addr, auth, dst, loop=self.loop)
                self.loop.run_until_complete(coro)
            self.assertIn('0x5b', str(ct.exception))


class TestCreateSocks5Connect(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)

    def tearDown(self):
        self.loop.close()

    def test_connect_success_anonymous(self):
        with fake_socks_srv(
                self.loop,
                b'\x05\x00\x05\x00\x00\x01\x01\x01\x01\x01\x04Wtest') as port:
            addr = aiosocks.Socks5Addr('127.0.0.1', port)
            auth = aiosocks.Socks5Auth('usr', 'pwd')
            dst = ('python.org', 80)

            coro = aiosocks.create_connection(
                None, addr, auth, dst, loop=self.loop)
            transport, protocol = self.loop.run_until_complete(coro)

            self.assertEqual(protocol.proxy_sockname, ('1.1.1.1', 1111))

            data = self.loop.run_until_complete(
                protocol._stream_reader.read(4))
            self.assertEqual(data, b'test')

            transport.close()

    def test_connect_success_usr_pwd(self):
        with fake_socks_srv(
                self.loop,
                b'\x05\x02\x01\x00\x05\x00\x00\x01\x01\x01\x01\x01\x04Wtest'
        ) as port:
            addr = aiosocks.Socks5Addr('127.0.0.1', port)
            auth = aiosocks.Socks5Auth('usr', 'pwd')
            dst = ('python.org', 80)

            coro = aiosocks.create_connection(
                None, addr, auth, dst, loop=self.loop)
            transport, protocol = self.loop.run_until_complete(coro)

            self.assertEqual(protocol.proxy_sockname, ('1.1.1.1', 1111))

            data = self.loop.run_until_complete(
                protocol._stream_reader.read(4))
            self.assertEqual(data, b'test')
            transport.close()

    def test_auth_ver_err(self):
        with fake_socks_srv(self.loop, b'\x04\x02') as port:
            addr = aiosocks.Socks5Addr('127.0.0.1', port)
            auth = aiosocks.Socks5Auth('usr', 'pwd')
            dst = ('python.org', 80)

            with self.assertRaises(aiosocks.SocksError) as ct:
                coro = aiosocks.create_connection(
                    None, addr, auth, dst, loop=self.loop)
                self.loop.run_until_complete(coro)
            self.assertIn('invalid version', str(ct.exception))

    def test_auth_method_rejected(self):
        with fake_socks_srv(self.loop, b'\x05\xFF') as port:
            addr = aiosocks.Socks5Addr('127.0.0.1', port)
            auth = aiosocks.Socks5Auth('usr', 'pwd')
            dst = ('python.org', 80)

            with self.assertRaises(aiosocks.SocksError) as ct:
                coro = aiosocks.create_connection(
                    None, addr, auth, dst, loop=self.loop)
                self.loop.run_until_complete(coro)
            self.assertIn('authentication methods were rejected',
                          str(ct.exception))

    def test_auth_status_invalid(self):
        with fake_socks_srv(self.loop, b'\x05\xF0') as port:
            addr = aiosocks.Socks5Addr('127.0.0.1', port)
            auth = aiosocks.Socks5Auth('usr', 'pwd')
            dst = ('python.org', 80)

            with self.assertRaises(aiosocks.SocksError) as ct:
                coro = aiosocks.create_connection(
                    None, addr, auth, dst, loop=self.loop)
                self.loop.run_until_complete(coro)
            self.assertIn('invalid data', str(ct.exception))

    def test_auth_status_invalid2(self):
        with fake_socks_srv(self.loop, b'\x05\x02\x02\x00') as port:
            addr = aiosocks.Socks5Addr('127.0.0.1', port)
            auth = aiosocks.Socks5Auth('usr', 'pwd')
            dst = ('python.org', 80)

            with self.assertRaises(aiosocks.SocksError) as ct:
                coro = aiosocks.create_connection(
                    None, addr, auth, dst, loop=self.loop)
                self.loop.run_until_complete(coro)
            self.assertIn('invalid data', str(ct.exception))

    def test_auth_failed(self):
        with fake_socks_srv(self.loop, b'\x05\x02\x01\x01') as port:
            addr = aiosocks.Socks5Addr('127.0.0.1', port)
            auth = aiosocks.Socks5Auth('usr', 'pwd')
            dst = ('python.org', 80)

            with self.assertRaises(aiosocks.SocksError) as ct:
                coro = aiosocks.create_connection(
                    None, addr, auth, dst, loop=self.loop)
                self.loop.run_until_complete(coro)
            self.assertIn('authentication failed', str(ct.exception))

    def test_cmd_ver_err(self):
        with fake_socks_srv(self.loop,
                            b'\x05\x02\x01\x00\x04\x00\x00') as port:
            addr = aiosocks.Socks5Addr('127.0.0.1', port)
            auth = aiosocks.Socks5Auth('usr', 'pwd')
            dst = ('python.org', 80)

            with self.assertRaises(aiosocks.SocksError) as ct:
                coro = aiosocks.create_connection(
                    None, addr, auth, dst, loop=self.loop)
                self.loop.run_until_complete(coro)
            self.assertIn('invalid version', str(ct.exception))

    def test_cmd_not_granted(self):
        with fake_socks_srv(self.loop,
                            b'\x05\x02\x01\x00\x05\x01\x00') as port:
            addr = aiosocks.Socks5Addr('127.0.0.1', port)
            auth = aiosocks.Socks5Auth('usr', 'pwd')
            dst = ('python.org', 80)

            with self.assertRaises(aiosocks.SocksError) as ct:
                coro = aiosocks.create_connection(
                    None, addr, auth, dst, loop=self.loop)
                self.loop.run_until_complete(coro)
            self.assertIn('General SOCKS server failure', str(ct.exception))

    def test_invalid_address_type(self):
        with fake_socks_srv(self.loop,
                            b'\x05\x02\x01\x00\x05\x00\x00\xFF') as port:
            addr = aiosocks.Socks5Addr('127.0.0.1', port)
            auth = aiosocks.Socks5Auth('usr', 'pwd')
            dst = ('python.org', 80)

            with self.assertRaises(aiosocks.SocksError) as ct:
                coro = aiosocks.create_connection(
                    None, addr, auth, dst, loop=self.loop)
                self.loop.run_until_complete(coro)
            self.assertIn('invalid data', str(ct.exception))

    def test_atype_ipv4(self):
        with fake_socks_srv(
                self.loop,
                b'\x05\x02\x01\x00\x05\x00\x00\x01\x01\x01\x01\x01\x04W'
        ) as port:
            addr = aiosocks.Socks5Addr('127.0.0.1', port)
            auth = aiosocks.Socks5Auth('usr', 'pwd')
            dst = ('python.org', 80)

            coro = aiosocks.create_connection(
                None, addr, auth, dst, loop=self.loop)
            transport, protocol = self.loop.run_until_complete(coro)

            self.assertEqual(protocol.proxy_sockname, ('1.1.1.1', 1111))

            transport.close()

    def test_atype_ipv6(self):
        with fake_socks_srv(
                self.loop,
                b'\x05\x02\x01\x00\x05\x00\x00\x04\x00\x00\x00\x00'
                b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x11\x04W'
        ) as port:
            addr = aiosocks.Socks5Addr('127.0.0.1', port)
            auth = aiosocks.Socks5Auth('usr', 'pwd')
            dst = ('python.org', 80)

            coro = aiosocks.create_connection(
                None, addr, auth, dst, loop=self.loop)
            transport, protocol = self.loop.run_until_complete(coro)

            self.assertEqual(protocol.proxy_sockname, ('::111', 1111))

            transport.close()

    def test_atype_domain(self):
        with fake_socks_srv(
                self.loop,
                b'\x05\x02\x01\x00\x05\x00\x00\x03\x0apython.org\x04W'
        ) as port:
            addr = aiosocks.Socks5Addr('127.0.0.1', port)
            auth = aiosocks.Socks5Auth('usr', 'pwd')
            dst = ('python.org', 80)

            coro = aiosocks.create_connection(
                None, addr, auth, dst, loop=self.loop)
            transport, protocol = self.loop.run_until_complete(coro)

            self.assertEqual(protocol.proxy_sockname, (b'python.org', 1111))

            transport.close()


class TestSocksConnector(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)

    def tearDown(self):
        self.loop.close()

    def test_http_connect(self):
        with fake_socks4_srv(self.loop) as proxy_port:
            addr = aiosocks.Socks4Addr('127.0.0.1', proxy_port)

            conn = SocksConnector(proxy=addr, proxy_auth=None, loop=self.loop,
                                  remote_resolve=False)

            with http_srv(self.loop) as url:
                with aiohttp.ClientSession(connector=conn,
                                           loop=self.loop) as ses:
                    @asyncio.coroutine
                    def make_req():
                        return (yield from ses.request('get', url=url))

                    resp = self.loop.run_until_complete(make_req())

                    self.assertEqual(resp.status, 200)

                    content = self.loop.run_until_complete(resp.text())
                    self.assertEqual(content, 'Test message')

                    resp.close()

    def test_https_connect(self):
        with fake_socks4_srv(self.loop) as proxy_port:
            addr = aiosocks.Socks4Addr('127.0.0.1', proxy_port)

            conn = SocksConnector(proxy=addr, proxy_auth=None, loop=self.loop,
                                  remote_resolve=False, verify_ssl=False)

            with http_srv(self.loop, use_ssl=True) as url:
                with aiohttp.ClientSession(connector=conn,
                                           loop=self.loop) as ses:
                    @asyncio.coroutine
                    def make_req():
                        return (yield from ses.request('get', url=url))

                    resp = self.loop.run_until_complete(make_req())

                    self.assertEqual(resp.status, 200)

                    content = self.loop.run_until_complete(resp.text())
                    self.assertEqual(content, 'Test message')

                    resp.close()
