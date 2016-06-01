import unittest
import asyncio
import aiosocks
import aiohttp
import pytest
from unittest import mock
from aiohttp.client_reqrep import ClientRequest
from aiosocks.connector import SocksConnector, proxy_connector
from .helpers import fake_coroutine


class TestSocksConnector(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)

    def tearDown(self):
        self.loop.close()

    def test_properties(self):
        addr = aiosocks.Socks4Addr('localhost')
        auth = aiosocks.Socks4Auth('login')
        conn = SocksConnector(addr, auth, loop=self.loop)
        self.assertIs(conn.proxy, addr)
        self.assertIs(conn.proxy_auth, auth)

    @mock.patch('aiosocks.connector.create_connection')
    def test_connect_proxy_ip(self, cr_conn_mock):
        tr, proto = mock.Mock(name='transport'), mock.Mock(name='protocol')
        cr_conn_mock.side_effect = \
            fake_coroutine((tr, proto)).side_effect

        loop_mock = mock.Mock()

        req = ClientRequest('GET', 'http://python.org', loop=self.loop)
        connector = SocksConnector(aiosocks.Socks5Addr('127.0.0.1'),
                                   None, loop=loop_mock)

        loop_mock.getaddrinfo = fake_coroutine([mock.MagicMock()])

        conn = self.loop.run_until_complete(connector.connect(req))

        self.assertTrue(loop_mock.getaddrinfo.is_called)
        self.assertIs(conn._transport, tr)

        conn.close()

    @mock.patch('aiosocks.connector.create_connection')
    def test_connect_proxy_domain(self, cr_conn_mock):
        tr, proto = mock.Mock(name='transport'), mock.Mock(name='protocol')
        cr_conn_mock.side_effect = \
            fake_coroutine((tr, proto)).side_effect
        loop_mock = mock.Mock()

        req = ClientRequest('GET', 'http://python.org', loop=self.loop)
        connector = SocksConnector(aiosocks.Socks5Addr('proxy.example'),
                                   None, loop=loop_mock)

        connector._resolve_host = fake_coroutine([mock.MagicMock()])

        conn = self.loop.run_until_complete(connector.connect(req))

        self.assertTrue(connector._resolve_host.is_called)
        self.assertEqual(connector._resolve_host.call_count, 1)
        self.assertIs(conn._transport, tr)

        conn.close()

    @mock.patch('aiosocks.connector.create_connection')
    def test_connect_remote_resolve(self, cr_conn_mock):
        tr, proto = mock.Mock(name='transport'), mock.Mock(name='protocol')
        cr_conn_mock.side_effect = \
            fake_coroutine((tr, proto)).side_effect

        req = ClientRequest('GET', 'http://python.org', loop=self.loop)
        connector = SocksConnector(aiosocks.Socks5Addr('127.0.0.1'),
                                   None, loop=self.loop, remote_resolve=True)

        connector._resolve_host = fake_coroutine([mock.MagicMock()])

        conn = self.loop.run_until_complete(connector.connect(req))

        self.assertEqual(connector._resolve_host.call_count, 0)

        conn.close()

    @mock.patch('aiosocks.connector.create_connection')
    def test_connect_locale_resolve(self, cr_conn_mock):
        tr, proto = mock.Mock(name='transport'), mock.Mock(name='protocol')
        cr_conn_mock.side_effect = \
            fake_coroutine((tr, proto)).side_effect

        req = ClientRequest('GET', 'http://python.org', loop=self.loop)
        connector = SocksConnector(aiosocks.Socks5Addr('proxy.example'),
                                   None, loop=self.loop, remote_resolve=False)

        connector._resolve_host = fake_coroutine([mock.MagicMock()])

        conn = self.loop.run_until_complete(connector.connect(req))

        self.assertTrue(connector._resolve_host.is_called)
        self.assertEqual(connector._resolve_host.call_count, 2)

        conn.close()

    @mock.patch('aiosocks.connector.create_connection')
    def test_proxy_connect_fail(self, cr_conn_mock):
        loop_mock = mock.Mock()
        cr_conn_mock.side_effect = \
            fake_coroutine(aiosocks.SocksConnectionError()).side_effect

        req = ClientRequest('GET', 'http://python.org', loop=self.loop)
        connector = SocksConnector(aiosocks.Socks5Addr('127.0.0.1'),
                                   None, loop=loop_mock)

        loop_mock.getaddrinfo = fake_coroutine([mock.MagicMock()])

        with self.assertRaises(aiohttp.ProxyConnectionError):
            self.loop.run_until_complete(connector.connect(req))

    @mock.patch('aiosocks.connector.create_connection')
    def test_proxy_negotiate_fail(self, cr_conn_mock):
        loop_mock = mock.Mock()
        cr_conn_mock.side_effect = \
            fake_coroutine(aiosocks.SocksError()).side_effect

        req = ClientRequest('GET', 'http://python.org', loop=self.loop)
        connector = SocksConnector(aiosocks.Socks5Addr('127.0.0.1'),
                                   None, loop=loop_mock)

        loop_mock.getaddrinfo = fake_coroutine([mock.MagicMock()])

        with self.assertRaises(aiosocks.SocksError):
            self.loop.run_until_complete(connector.connect(req))


def test_proxy_connector():
    socks4_addr = aiosocks.Socks4Addr('h')
    socks5_addr = aiosocks.Socks5Addr('h')
    http_addr = aiosocks.HttpProxyAddr('http://proxy')

    loop = asyncio.new_event_loop()

    assert isinstance(proxy_connector(socks4_addr, loop=loop), SocksConnector)
    assert isinstance(proxy_connector(socks5_addr, loop=loop), SocksConnector)
    assert isinstance(proxy_connector(http_addr, loop=loop),
                      aiohttp.ProxyConnector)

    with pytest.raises(ValueError):
        proxy_connector(None)
