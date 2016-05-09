import unittest
import asyncio
import aiosocks
import aiohttp
from unittest import mock
from asyncio import coroutine
from aiohttp.client_reqrep import ClientRequest
from aiosocks.connector import SocksConnector


class TestSocksConnector(unittest.TestCase):
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

        return mock.Mock(side_effect=coroutine(coro))

    def test_connect_proxy_ip(self):
        loop_mock = mock.Mock()

        req = ClientRequest('GET', 'http://python.org', loop=self.loop)
        connector = SocksConnector(aiosocks.Socks5Addr('127.0.0.1'),
                                   None, loop=loop_mock)

        loop_mock.getaddrinfo = self._fake_coroutine([mock.MagicMock()])

        tr, proto = mock.Mock(name='transport'), mock.Mock(name='protocol')
        proto.negotiate_done = self._fake_coroutine(True)
        loop_mock.create_connection = self._fake_coroutine((tr, proto))

        conn = self.loop.run_until_complete(connector.connect(req))

        self.assertTrue(loop_mock.getaddrinfo.is_called)
        self.assertIs(conn._transport, tr)
        self.assertTrue(isinstance(conn._protocol, aiohttp.parsers.StreamProtocol))

        conn.close()

    def test_connect_proxy_domain(self):
        loop_mock = mock.Mock()

        req = ClientRequest('GET', 'http://python.org', loop=self.loop)
        connector = SocksConnector(aiosocks.Socks5Addr('proxy.example'),
                                   None, loop=loop_mock)

        connector._resolve_host = self._fake_coroutine([mock.MagicMock()])

        tr, proto = mock.Mock(name='transport'), mock.Mock(name='protocol')
        proto.negotiate_done = self._fake_coroutine(True)
        loop_mock.create_connection = self._fake_coroutine((tr, proto))

        conn = self.loop.run_until_complete(connector.connect(req))

        self.assertTrue(connector._resolve_host.is_called)
        self.assertEqual(connector._resolve_host.call_count, 1)
        self.assertIs(conn._transport, tr)
        self.assertTrue(isinstance(conn._protocol, aiohttp.parsers.StreamProtocol))

        conn.close()

    def test_connect_locale_resolve(self):
        loop_mock = mock.Mock()

        req = ClientRequest('GET', 'http://python.org', loop=self.loop)
        connector = SocksConnector(aiosocks.Socks5Addr('proxy.example'),
                                   None, loop=loop_mock, remote_resolve=False)

        connector._resolve_host = self._fake_coroutine([mock.MagicMock()])

        tr, proto = mock.Mock(name='transport'), mock.Mock(name='protocol')
        proto.negotiate_done = self._fake_coroutine(True)
        loop_mock.create_connection = self._fake_coroutine((tr, proto))

        conn = self.loop.run_until_complete(connector.connect(req))

        self.assertTrue(connector._resolve_host.is_called)
        self.assertEqual(connector._resolve_host.call_count, 2)
        self.assertIs(conn._transport, tr)
        self.assertTrue(isinstance(conn._protocol, aiohttp.parsers.StreamProtocol))

        conn.close()

    def test_proxy_connect_fail(self):
        loop_mock = mock.Mock()

        req = ClientRequest('GET', 'http://python.org', loop=self.loop)
        connector = SocksConnector(aiosocks.Socks5Addr('127.0.0.1'),
                                   None, loop=loop_mock)

        loop_mock.getaddrinfo = self._fake_coroutine([mock.MagicMock()])
        loop_mock.create_connection = self._fake_coroutine(OSError())

        with self.assertRaises(aiohttp.ProxyConnectionError):
            self.loop.run_until_complete(connector.connect(req))

    def test_proxy_negotiate_fail(self):
        loop_mock = mock.Mock()

        req = ClientRequest('GET', 'http://python.org', loop=self.loop)
        connector = SocksConnector(aiosocks.Socks5Addr('127.0.0.1'),
                                   None, loop=loop_mock)

        loop_mock.getaddrinfo = self._fake_coroutine([mock.MagicMock()])

        tr, proto = mock.Mock(name='transport'), mock.Mock(name='protocol')
        proto.negotiate_done = self._fake_coroutine(aiosocks.SocksError())
        loop_mock.create_connection = self._fake_coroutine((tr, proto))

        with self.assertRaises(aiosocks.SocksError):
            self.loop.run_until_complete(connector.connect(req))
