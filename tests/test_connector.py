import ssl

import aiosocks
import aiohttp
import pytest
from yarl import URL
from unittest import mock
from aiohttp.test_utils import make_mocked_coro
from aiohttp import BasicAuth
from aiosocks.connector import ProxyConnector, ProxyClientRequest
from aiosocks.helpers import Socks4Auth, Socks5Auth


async def test_connect_proxy_ip(loop):
    tr, proto = mock.Mock(name='transport'), mock.Mock(name='protocol')

    with mock.patch('aiosocks.connector.create_connection',
                    make_mocked_coro((tr, proto))):
        loop.getaddrinfo = make_mocked_coro(
             [[0, 0, 0, 0, ['127.0.0.1', 1080]]])

        req = ProxyClientRequest(
            'GET', URL('http://python.org'), loop=loop,
            proxy=URL('socks5://proxy.org'))
        connector = ProxyConnector(loop=loop)
        conn = await connector.connect(req)

    assert loop.getaddrinfo.called
    assert conn.protocol is proto

    conn.close()


async def test_connect_proxy_domain():
    tr, proto = mock.Mock(name='transport'), mock.Mock(name='protocol')

    with mock.patch('aiosocks.connector.create_connection',
                    make_mocked_coro((tr, proto))):
        loop_mock = mock.Mock()

        req = ProxyClientRequest(
            'GET', URL('http://python.org'),  loop=loop_mock,
            proxy=URL('socks5://proxy.example'))
        connector = ProxyConnector(loop=loop_mock)

        connector._resolve_host = make_mocked_coro([mock.MagicMock()])
        conn = await connector.connect(req)

    assert connector._resolve_host.call_count == 1
    assert conn.protocol is proto

    conn.close()


async def test_connect_remote_resolve(loop):
    tr, proto = mock.Mock(name='transport'), mock.Mock(name='protocol')

    with mock.patch('aiosocks.connector.create_connection',
                    make_mocked_coro((tr, proto))):
        req = ProxyClientRequest(
            'GET', URL('http://python.org'), loop=loop,
            proxy=URL('socks5://127.0.0.1'))
        connector = ProxyConnector(loop=loop, remote_resolve=True)
        connector._resolve_host = make_mocked_coro([mock.MagicMock()])

        conn = await connector.connect(req)

    assert connector._resolve_host.call_count == 1
    assert conn.protocol is proto

    conn.close()


async def test_connect_locale_resolve(loop):
    tr, proto = mock.Mock(name='transport'), mock.Mock(name='protocol')

    with mock.patch('aiosocks.connector.create_connection',
                    make_mocked_coro((tr, proto))):
        req = ProxyClientRequest(
            'GET', URL('http://python.org'), loop=loop,
            proxy=URL('socks5://proxy.example'))
        connector = ProxyConnector(loop=loop, remote_resolve=False)
        connector._resolve_host = make_mocked_coro([mock.MagicMock()])

        conn = await connector.connect(req)

    assert connector._resolve_host.call_count == 2
    assert conn.protocol is proto

    conn.close()


@pytest.mark.parametrize('remote_resolve', [True, False])
async def test_resolve_host_fail(loop, remote_resolve):
    tr, proto = mock.Mock(name='transport'), mock.Mock(name='protocol')

    with mock.patch('aiosocks.connector.create_connection',
                    make_mocked_coro((tr, proto))):
        req = ProxyClientRequest(
            'GET', URL('http://python.org'), loop=loop,
            proxy=URL('socks5://proxy.example'))
        connector = ProxyConnector(loop=loop, remote_resolve=remote_resolve)
        connector._resolve_host = make_mocked_coro(raise_exception=OSError())

        with pytest.raises(aiohttp.ClientConnectorError):
            await connector.connect(req)


@pytest.mark.parametrize('exc', [
    (ssl.CertificateError, aiohttp.ClientConnectorCertificateError),
    (ssl.SSLError, aiohttp.ClientConnectorSSLError),
    (aiosocks.SocksConnectionError, aiohttp.ClientProxyConnectionError)])
async def test_proxy_connect_fail(loop, exc):
    loop_mock = mock.Mock()
    loop_mock.getaddrinfo = make_mocked_coro(
        [[0, 0, 0, 0, ['127.0.0.1', 1080]]])
    cc_coro = make_mocked_coro(
        raise_exception=exc[0]())

    with mock.patch('aiosocks.connector.create_connection', cc_coro):
        req = ProxyClientRequest(
            'GET', URL('http://python.org'), loop=loop,
            proxy=URL('socks5://127.0.0.1'))
        connector = ProxyConnector(loop=loop_mock)

        with pytest.raises(exc[1]):
            await connector.connect(req)


async def test_proxy_negotiate_fail(loop):
    loop_mock = mock.Mock()
    loop_mock.getaddrinfo = make_mocked_coro(
        [[0, 0, 0, 0, ['127.0.0.1', 1080]]])

    with mock.patch('aiosocks.connector.create_connection',
                    make_mocked_coro(raise_exception=aiosocks.SocksError())):
        req = ProxyClientRequest(
            'GET', URL('http://python.org'), loop=loop,
            proxy=URL('socks5://127.0.0.1'))
        connector = ProxyConnector(loop=loop_mock)

        with pytest.raises(aiosocks.SocksError):
            await connector.connect(req)


async def test_proxy_connect_http(loop):
    tr, proto = mock.Mock(name='transport'), mock.Mock(name='protocol')
    loop_mock = mock.Mock()
    loop_mock.getaddrinfo = make_mocked_coro([
        [0, 0, 0, 0, ['127.0.0.1', 1080]]])
    loop_mock.create_connection = make_mocked_coro((tr, proto))

    req = ProxyClientRequest(
        'GET', URL('http://python.org'), loop=loop,
        proxy=URL('http://127.0.0.1'))
    connector = ProxyConnector(loop=loop_mock)

    await connector.connect(req)


@pytest.mark.parametrize('proxy', [
    (URL('socks4://proxy.org'), Socks4Auth('login')),
    (URL('socks5://proxy.org'), Socks5Auth('login', 'password')),
    (URL('http://proxy.org'), BasicAuth('login')), (None, BasicAuth('login')),
    (URL('socks4://proxy.org'), None), (None, None)])
def test_proxy_client_request_valid(proxy, loop):
    proxy, proxy_auth = proxy
    p = ProxyClientRequest('GET', URL('http://python.org'),
                           proxy=proxy, proxy_auth=proxy_auth, loop=loop)
    assert p.proxy is proxy
    assert p.proxy_auth is proxy_auth


def test_proxy_client_request_invalid(loop):
    with pytest.raises(ValueError) as cm:
        ProxyClientRequest(
            'GET', URL('http://python.org'),
            proxy=URL('socks6://proxy.org'), proxy_auth=None, loop=loop)
    assert 'Only http, socks4 and socks5 proxies are supported' in str(cm)

    with pytest.raises(ValueError) as cm:
        ProxyClientRequest(
            'GET', URL('http://python.org'), loop=loop,
            proxy=URL('http://proxy.org'), proxy_auth=Socks4Auth('l'))
    assert 'proxy_auth must be None or BasicAuth() ' \
           'tuple for http proxy' in str(cm)

    with pytest.raises(ValueError) as cm:
        ProxyClientRequest(
            'GET', URL('http://python.org'), loop=loop,
            proxy=URL('socks4://proxy.org'), proxy_auth=BasicAuth('l'))
    assert 'proxy_auth must be None or Socks4Auth() ' \
           'tuple for socks4 proxy' in str(cm)

    with pytest.raises(ValueError) as cm:
        ProxyClientRequest(
            'GET', URL('http://python.org'), loop=loop,
            proxy=URL('socks5://proxy.org'), proxy_auth=Socks4Auth('l'))
    assert 'proxy_auth must be None or Socks5Auth() ' \
           'tuple for socks5 proxy' in str(cm)
