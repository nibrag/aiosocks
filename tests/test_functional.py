import unittest
import aiohttp
import aiosocks
import asyncio
from aiohttp import web
from aiosocks.connector import SocksConnector

try:
    from asyncio import ensure_future
except ImportError:
    ensure_future = asyncio.async

from .helpers import fake_socks_srv, find_unused_port


class TestCreateSocks4Connection(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)

    def tearDown(self):
        self.loop.close()

    def test_connect_success(self):
        server, port = self.loop.run_until_complete(
            fake_socks_srv(self.loop, b'\x00\x5a\x04W\x01\x01\x01\x01test')
        )
        addr = aiosocks.Socks4Addr('127.0.0.1', port)
        auth = aiosocks.Socks4Auth('usr')
        dst = ('python.org', 80)

        coro = aiosocks.create_connection(
            None, addr, auth, dst, loop=self.loop)
        transport, protocol = self.loop.run_until_complete(coro)

        self.assertEqual(protocol.proxy_sockname, ('1.1.1.1', 1111))

        data = self.loop.run_until_complete(protocol._stream_reader.read(4))
        self.assertEqual(data, b'test')

        transport.close()
        server.close()
        self.loop.run_until_complete(server.wait_closed())

    def test_invalid_data(self):
        server, port = self.loop.run_until_complete(
            fake_socks_srv(self.loop, b'\x01\x5a\x04W\x01\x01\x01\x01')
        )
        addr = aiosocks.Socks4Addr('127.0.0.1', port)
        auth = aiosocks.Socks4Auth('usr')
        dst = ('python.org', 80)

        with self.assertRaises(aiosocks.SocksError) as ct:
            coro = aiosocks.create_connection(
                None, addr, auth, dst, loop=self.loop)
            self.loop.run_until_complete(coro)
        self.assertIn('invalid data', str(ct.exception))

        server.close()
        self.loop.run_until_complete(server.wait_closed())

    def test_socks_srv_error(self):
        server, port = self.loop.run_until_complete(
            fake_socks_srv(self.loop, b'\x00\x5b\x04W\x01\x01\x01\x01')
        )
        addr = aiosocks.Socks4Addr('127.0.0.1', port)
        auth = aiosocks.Socks4Auth('usr')
        dst = ('python.org', 80)

        with self.assertRaises(aiosocks.SocksError) as ct:
            coro = aiosocks.create_connection(
                None, addr, auth, dst, loop=self.loop)
            self.loop.run_until_complete(coro)
        self.assertIn('0x5b', str(ct.exception))

        server.close()
        self.loop.run_until_complete(server.wait_closed())


class TestCreateSocks5Connect(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)

    def tearDown(self):
        self.loop.close()

    def test_connect_success_anonymous(self):
        server, port = self.loop.run_until_complete(
            fake_socks_srv(
                self.loop,
                b'\x05\x00\x05\x00\x00\x01\x01\x01\x01\x01\x04Wtest'
            )
        )
        addr = aiosocks.Socks5Addr('127.0.0.1', port)
        auth = aiosocks.Socks5Auth('usr', 'pwd')
        dst = ('python.org', 80)

        coro = aiosocks.create_connection(
            None, addr, auth, dst, loop=self.loop)
        transport, protocol = self.loop.run_until_complete(coro)

        self.assertEqual(protocol.proxy_sockname, ('1.1.1.1', 1111))

        data = self.loop.run_until_complete(protocol._stream_reader.read(4))
        self.assertEqual(data, b'test')

        transport.close()
        server.close()
        self.loop.run_until_complete(server.wait_closed())

    def test_connect_success_usr_pwd(self):
        server, port = self.loop.run_until_complete(
            fake_socks_srv(
                self.loop,
                b'\x05\x02\x01\x00\x05\x00\x00\x01\x01\x01\x01\x01\x04Wtest'
            )
        )
        addr = aiosocks.Socks5Addr('127.0.0.1', port)
        auth = aiosocks.Socks5Auth('usr', 'pwd')
        dst = ('python.org', 80)

        coro = aiosocks.create_connection(
            None, addr, auth, dst, loop=self.loop)
        transport, protocol = self.loop.run_until_complete(coro)

        self.assertEqual(protocol.proxy_sockname, ('1.1.1.1', 1111))

        data = self.loop.run_until_complete(protocol._stream_reader.read(4))
        self.assertEqual(data, b'test')

        transport.close()
        server.close()
        self.loop.run_until_complete(server.wait_closed())

    def test_auth_ver_err(self):
        server, port = self.loop.run_until_complete(
            fake_socks_srv(self.loop, b'\x04\x02')
        )
        addr = aiosocks.Socks5Addr('127.0.0.1', port)
        auth = aiosocks.Socks5Auth('usr', 'pwd')
        dst = ('python.org', 80)

        with self.assertRaises(aiosocks.SocksError) as ct:
            coro = aiosocks.create_connection(
                None, addr, auth, dst, loop=self.loop)
            self.loop.run_until_complete(coro)
        self.assertIn('invalid version', str(ct.exception))

        server.close()
        self.loop.run_until_complete(server.wait_closed())

    def test_auth_method_rejected(self):
        server, port = self.loop.run_until_complete(
            fake_socks_srv(self.loop, b'\x05\xFF')
        )
        addr = aiosocks.Socks5Addr('127.0.0.1', port)
        auth = aiosocks.Socks5Auth('usr', 'pwd')
        dst = ('python.org', 80)

        with self.assertRaises(aiosocks.SocksError) as ct:
            coro = aiosocks.create_connection(
                None, addr, auth, dst, loop=self.loop)
            self.loop.run_until_complete(coro)
        self.assertIn('authentication methods were rejected',
                      str(ct.exception))

        server.close()
        self.loop.run_until_complete(server.wait_closed())

    def test_auth_status_invalid(self):
        server, port = self.loop.run_until_complete(
            fake_socks_srv(self.loop, b'\x05\xF0')
        )
        addr = aiosocks.Socks5Addr('127.0.0.1', port)
        auth = aiosocks.Socks5Auth('usr', 'pwd')
        dst = ('python.org', 80)

        with self.assertRaises(aiosocks.SocksError) as ct:
            coro = aiosocks.create_connection(
                None, addr, auth, dst, loop=self.loop)
            self.loop.run_until_complete(coro)
        self.assertIn('invalid data', str(ct.exception))

        server.close()
        self.loop.run_until_complete(server.wait_closed())

    def test_auth_status_invalid2(self):
        server, port = self.loop.run_until_complete(
            fake_socks_srv(self.loop, b'\x05\x02\x02\x00')
        )
        addr = aiosocks.Socks5Addr('127.0.0.1', port)
        auth = aiosocks.Socks5Auth('usr', 'pwd')
        dst = ('python.org', 80)

        with self.assertRaises(aiosocks.SocksError) as ct:
            coro = aiosocks.create_connection(
                None, addr, auth, dst, loop=self.loop)
            self.loop.run_until_complete(coro)
        self.assertIn('invalid data', str(ct.exception))

        server.close()
        self.loop.run_until_complete(server.wait_closed())

    def test_auth_failed(self):
        server, port = self.loop.run_until_complete(
            fake_socks_srv(self.loop, b'\x05\x02\x01\x01')
        )
        addr = aiosocks.Socks5Addr('127.0.0.1', port)
        auth = aiosocks.Socks5Auth('usr', 'pwd')
        dst = ('python.org', 80)

        with self.assertRaises(aiosocks.SocksError) as ct:
            coro = aiosocks.create_connection(
                None, addr, auth, dst, loop=self.loop)
            self.loop.run_until_complete(coro)
        self.assertIn('authentication failed', str(ct.exception))

        server.close()
        self.loop.run_until_complete(server.wait_closed())

    def test_cmd_ver_err(self):
        server, port = self.loop.run_until_complete(
            fake_socks_srv(self.loop, b'\x05\x02\x01\x00\x04\x00\x00')
        )
        addr = aiosocks.Socks5Addr('127.0.0.1', port)
        auth = aiosocks.Socks5Auth('usr', 'pwd')
        dst = ('python.org', 80)

        with self.assertRaises(aiosocks.SocksError) as ct:
            coro = aiosocks.create_connection(
                None, addr, auth, dst, loop=self.loop)
            self.loop.run_until_complete(coro)
        self.assertIn('invalid version', str(ct.exception))

        server.close()
        self.loop.run_until_complete(server.wait_closed())

    def test_cmd_not_granted(self):
        server, port = self.loop.run_until_complete(
            fake_socks_srv(self.loop, b'\x05\x02\x01\x00\x05\x01\x00')
        )
        addr = aiosocks.Socks5Addr('127.0.0.1', port)
        auth = aiosocks.Socks5Auth('usr', 'pwd')
        dst = ('python.org', 80)

        with self.assertRaises(aiosocks.SocksError) as ct:
            coro = aiosocks.create_connection(
                None, addr, auth, dst, loop=self.loop)
            self.loop.run_until_complete(coro)
        self.assertIn('General SOCKS server failure', str(ct.exception))

        server.close()
        self.loop.run_until_complete(server.wait_closed())

    def test_invalid_address_type(self):
        server, port = self.loop.run_until_complete(
            fake_socks_srv(self.loop, b'\x05\x02\x01\x00\x05\x00\x00\xFF')
        )
        addr = aiosocks.Socks5Addr('127.0.0.1', port)
        auth = aiosocks.Socks5Auth('usr', 'pwd')
        dst = ('python.org', 80)

        with self.assertRaises(aiosocks.SocksError) as ct:
            coro = aiosocks.create_connection(
                None, addr, auth, dst, loop=self.loop)
            self.loop.run_until_complete(coro)
        self.assertIn('invalid data', str(ct.exception))

        server.close()
        self.loop.run_until_complete(server.wait_closed())

    def test_atype_ipv4(self):
        server, port = self.loop.run_until_complete(
            fake_socks_srv(
                self.loop,
                b'\x05\x02\x01\x00\x05\x00\x00\x01\x01\x01\x01\x01\x04W'
            )
        )
        addr = aiosocks.Socks5Addr('127.0.0.1', port)
        auth = aiosocks.Socks5Auth('usr', 'pwd')
        dst = ('python.org', 80)

        coro = aiosocks.create_connection(
            None, addr, auth, dst, loop=self.loop)
        transport, protocol = self.loop.run_until_complete(coro)

        self.assertEqual(protocol.proxy_sockname, ('1.1.1.1', 1111))

        transport.close()
        server.close()
        self.loop.run_until_complete(server.wait_closed())

    def test_atype_ipv6(self):
        server, port = self.loop.run_until_complete(
            fake_socks_srv(
                self.loop,
                b'\x05\x02\x01\x00\x05\x00\x00\x04\x00\x00\x00\x00'
                b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x11\x04W')
        )
        addr = aiosocks.Socks5Addr('127.0.0.1', port)
        auth = aiosocks.Socks5Auth('usr', 'pwd')
        dst = ('python.org', 80)

        coro = aiosocks.create_connection(
            None, addr, auth, dst, loop=self.loop)
        transport, protocol = self.loop.run_until_complete(coro)

        self.assertEqual(protocol.proxy_sockname, ('::111', 1111))

        transport.close()
        server.close()
        self.loop.run_until_complete(server.wait_closed())

    def test_atype_domain(self):
        server, port = self.loop.run_until_complete(
            fake_socks_srv(
                self.loop,
                b'\x05\x02\x01\x00\x05\x00\x00\x03\x0apython.org\x04W'
            )
        )
        addr = aiosocks.Socks5Addr('127.0.0.1', port)
        auth = aiosocks.Socks5Auth('usr', 'pwd')
        dst = ('python.org', 80)

        coro = aiosocks.create_connection(
            None, addr, auth, dst, loop=self.loop)
        transport, protocol = self.loop.run_until_complete(coro)

        self.assertEqual(protocol.proxy_sockname, (b'python.org', 1111))

        transport.close()
        server.close()
        self.loop.run_until_complete(server.wait_closed())

