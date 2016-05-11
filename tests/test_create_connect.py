import unittest
import aiosocks
import asyncio
from unittest import mock
from .socks_serv import fake_socks_srv

try:
    from asyncio import ensure_future
except ImportError:
    ensure_future = asyncio.async


class TestCreateConnection(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)

    def tearDown(self):
        self.loop.close()

    def _fake_coroutine(self, return_value):
        def coro(*args, **kwargs):
            if isinstance(return_value, Exception):
                raise return_value
            return return_value

        return mock.Mock(side_effect=asyncio.coroutine(coro))

    def test_init(self):
        addr = aiosocks.Socks5Addr('localhost')
        auth = aiosocks.Socks5Auth('usr', 'pwd')
        dst = ('python.org', 80)

        # proxy argument
        with self.assertRaises(AssertionError) as ct:
            conn = aiosocks.create_connection(None, None, auth, dst)
            self.loop.run_until_complete(conn)
        self.assertEqual(str(ct.exception),
                         'proxy must be Socks4Addr() or Socks5Addr() tuple')

        with self.assertRaises(AssertionError) as ct:
            conn = aiosocks.create_connection(None, auth, auth, dst)
            self.loop.run_until_complete(conn)
        self.assertEqual(str(ct.exception),
                         'proxy must be Socks4Addr() or Socks5Addr() tuple')

        # proxy_auth
        with self.assertRaises(AssertionError) as ct:
            conn = aiosocks.create_connection(None, addr, addr, dst)
            self.loop.run_until_complete(conn)
        self.assertIn('proxy_auth must be None or Socks4Auth()',
                      str(ct.exception))

        # dst
        with self.assertRaises(AssertionError) as ct:
            conn = aiosocks.create_connection(None, addr, auth, None)
            self.loop.run_until_complete(conn)
        self.assertIn('invalid dst format, tuple("dst_host", dst_port))',
                      str(ct.exception))

        # addr and auth compatibility
        with self.assertRaises(ValueError) as ct:
            conn = aiosocks.create_connection(
                None, addr, aiosocks.Socks4Auth(''), dst
            )
            self.loop.run_until_complete(conn)
        self.assertIn('proxy is Socks5Addr but proxy_auth is not Socks5Auth',
                      str(ct.exception))

        with self.assertRaises(ValueError) as ct:
            conn = aiosocks.create_connection(
                None, aiosocks.Socks4Addr(''), auth, dst
            )
            self.loop.run_until_complete(conn)
        self.assertIn('proxy is Socks4Addr but proxy_auth is not Socks4Auth',
                      str(ct.exception))

        # test ssl, server_hostname
        with self.assertRaises(ValueError) as ct:
            conn = aiosocks.create_connection(
                None, addr, auth, dst, server_hostname='python.org'
            )
            self.loop.run_until_complete(conn)
        self.assertIn('server_hostname is only meaningful with ssl',
                      str(ct.exception))

    def test_connection_fail(self):
        addr = aiosocks.Socks5Addr('localhost')
        auth = aiosocks.Socks5Auth('usr', 'pwd')
        dst = ('python.org', 80)

        loop_mock = mock.Mock()
        loop_mock.create_connection = self._fake_coroutine(OSError())

        with self.assertRaises(aiosocks.SocksConnectionError):
            conn = aiosocks.create_connection(
                None, addr, auth, dst, loop=loop_mock
            )
            self.loop.run_until_complete(conn)


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

        _, addr = protocol._negotiate_fut.result()
        self.assertEqual(addr, ('1.1.1.1', 1111))

        data = self.loop.run_until_complete(protocol._stream_reader.read(4))
        self.assertEqual(data, b'test')

        server.close()
        transport.close()

    def test_invalid_ver(self):
        server, port = self.loop.run_until_complete(
            fake_socks_srv(self.loop, b'\x01\x5a\x04W\x01\x01\x01\x01')
        )
        addr = aiosocks.Socks4Addr('127.0.0.1', port)
        auth = aiosocks.Socks4Auth('usr')
        dst = ('python.org', 80)

        with self.assertRaises(aiosocks.SocksError) as ct:
            coro = aiosocks.create_connection(
                None, addr, auth, dst, loop=self.loop)
            transport, protocol = self.loop.run_until_complete(coro)
            transport.close()
        self.assertIn('invalid data', str(ct.exception))

        server.close()

    def test_access_not_granted(self):
        server, port = self.loop.run_until_complete(
            fake_socks_srv(self.loop, b'\x00\x5b\x04W\x01\x01\x01\x01')
        )
        addr = aiosocks.Socks4Addr('127.0.0.1', port)
        auth = aiosocks.Socks4Auth('usr')
        dst = ('python.org', 80)

        with self.assertRaises(aiosocks.SocksError) as ct:
            coro = aiosocks.create_connection(
                None, addr, auth, dst, loop=self.loop)
            transport, protocol = self.loop.run_until_complete(coro)
            transport.close()
        self.assertIn('0x5b', str(ct.exception))

        server.close()


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

        _, addr = protocol._negotiate_fut.result()
        self.assertEqual(addr, ('1.1.1.1', 1111))

        data = self.loop.run_until_complete(protocol._stream_reader.read(4))
        self.assertEqual(data, b'test')

        server.close()
        transport.close()

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

        _, addr = protocol._negotiate_fut.result()
        self.assertEqual(addr, ('1.1.1.1', 1111))

        data = self.loop.run_until_complete(protocol._stream_reader.read(4))
        self.assertEqual(data, b'test')

        server.close()
        transport.close()

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
            transport, protocol = self.loop.run_until_complete(coro)
            transport.close()
        self.assertIn('invalid version', str(ct.exception))

        server.close()

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
            transport, protocol = self.loop.run_until_complete(coro)
            transport.close()
        self.assertIn('authentication methods were rejected',
                      str(ct.exception))

        server.close()

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
            transport, protocol = self.loop.run_until_complete(coro)
            transport.close()
        self.assertIn('invalid data', str(ct.exception))

        server.close()

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
            transport, protocol = self.loop.run_until_complete(coro)
            transport.close()
        self.assertIn('invalid data', str(ct.exception))

        server.close()

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
            transport, protocol = self.loop.run_until_complete(coro)
            transport.close()
        self.assertIn('authentication failed', str(ct.exception))

        server.close()

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
            transport, protocol = self.loop.run_until_complete(coro)
            transport.close()
        self.assertIn('invalid version', str(ct.exception))

        server.close()

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
            transport, protocol = self.loop.run_until_complete(coro)
            transport.close()
        self.assertIn('General SOCKS server failure', str(ct.exception))

        server.close()

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
            transport, protocol = self.loop.run_until_complete(coro)
            transport.close()
        self.assertIn('invalid data', str(ct.exception))

        server.close()

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

        _, addr = protocol._negotiate_fut.result()
        self.assertEqual(addr, ('1.1.1.1', 1111))

        transport.close()
        server.close()

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

        _, addr = protocol._negotiate_fut.result()
        self.assertEqual(addr, ('::111', 1111))

        transport.close()
        server.close()

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

        _, addr = protocol._negotiate_fut.result()
        self.assertEqual(addr, (b'python.org', 1111))

        transport.close()
        server.close()
