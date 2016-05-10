import unittest
import aiosocks
import asyncio
from unittest import mock

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

    def test_negotiate_fail(self):
        addr = aiosocks.Socks5Addr('localhost')
        auth = aiosocks.Socks5Auth('usr', 'pwd')
        dst = ('python.org', 80)

        transp, proto = mock.Mock(), mock.Mock()
        proto.negotiate_done = self._fake_coroutine(aiosocks.SocksError())

        loop_mock = mock.Mock()
        loop_mock.create_connection = self._fake_coroutine((transp, proto))

        with self.assertRaises(aiosocks.SocksError) as ct:
            conn = aiosocks.create_connection(
                None, addr, auth, dst, loop=loop_mock
            )
            self.loop.run_until_complete(conn)
        self.assertIn('Can not connect to python.org:80',
                      str(ct.exception))

    def test_create_protocol(self):
        addr = aiosocks.Socks5Addr('localhost')
        auth = aiosocks.Socks5Auth('usr', 'pwd')
        dst = ('python.org', 80)

        transp, proto = mock.Mock(), mock.Mock()
        proto.negotiate_done = self._fake_coroutine(True)

        loop_mock = mock.Mock()
        loop_mock.create_connection = self._fake_coroutine((transp, proto))

        user_proto = mock.Mock()

        conn = aiosocks.create_connection(
            lambda: user_proto, addr, auth, dst, loop=loop_mock
        )
        fut = ensure_future(conn, loop=self.loop)
        self.loop.run_until_complete(fut)

        transport, protocol = fut.result()
        self.assertIs(transport, transp)
        self.assertIs(protocol, user_proto)
        self.assertIs(transport._protocol, user_proto)
