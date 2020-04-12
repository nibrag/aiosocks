import pytest
import aiosocks
from aiohttp.test_utils import make_mocked_coro
from unittest import mock


async def test_create_connection_init():
    addr = aiosocks.Socks5Addr('localhost')
    auth = aiosocks.Socks5Auth('usr', 'pwd')
    dst = ('python.org', 80)

    # proxy argument
    with pytest.raises(AssertionError) as ct:
        await aiosocks.create_connection(None, None, auth, dst)
    assert 'proxy must be Socks4Addr() or Socks5Addr() tuple' in str(ct.value)

    with pytest.raises(AssertionError) as ct:
        await aiosocks.create_connection(None, auth, auth, dst)
    assert 'proxy must be Socks4Addr() or Socks5Addr() tuple' in str(ct.value)

    # proxy_auth
    with pytest.raises(AssertionError) as ct:
        await aiosocks.create_connection(None, addr, addr, dst)
    assert 'proxy_auth must be None or Socks4Auth()' in str(ct.value)

    # dst
    with pytest.raises(AssertionError) as ct:
        await aiosocks.create_connection(None, addr, auth, None)
    assert 'invalid dst format, tuple("dst_host", dst_port))' in str(ct.value)

    # addr and auth compatibility
    with pytest.raises(ValueError) as ct:
        await aiosocks.create_connection(
            None, addr, aiosocks.Socks4Auth(''), dst)
    assert 'proxy is Socks5Addr but proxy_auth is not Socks5Auth' \
           in str(ct.value)

    with pytest.raises(ValueError) as ct:
        await aiosocks.create_connection(
            None, aiosocks.Socks4Addr(''), auth, dst)
    assert 'proxy is Socks4Addr but proxy_auth is not Socks4Auth' \
           in str(ct.value)

    # test ssl, server_hostname
    with pytest.raises(ValueError) as ct:
        await aiosocks.create_connection(
            None, addr, auth, dst, server_hostname='python.org')
    assert 'server_hostname is only meaningful with ssl' in str(ct.value)


async def test_connection_fail():
    addr = aiosocks.Socks5Addr('localhost')
    auth = aiosocks.Socks5Auth('usr', 'pwd')
    dst = ('python.org', 80)

    loop_mock = mock.Mock()
    loop_mock.create_connection = make_mocked_coro(raise_exception=OSError())

    with pytest.raises(aiosocks.SocksConnectionError):
        await aiosocks.create_connection(
            None, addr, auth, dst, loop=loop_mock)


async def test_negotiate_fail():
    addr = aiosocks.Socks5Addr('localhost')
    auth = aiosocks.Socks5Auth('usr', 'pwd')
    dst = ('python.org', 80)

    loop_mock = mock.Mock()
    loop_mock.create_connection = make_mocked_coro((mock.Mock(), mock.Mock()))

    with mock.patch('aiosocks.asyncio.Future') as future_mock:
        future_mock.side_effect = make_mocked_coro(
            raise_exception=aiosocks.SocksError())

        with pytest.raises(aiosocks.SocksError):
            await aiosocks.create_connection(
                None, addr, auth, dst, loop=loop_mock)


async def test_open_connection():
    addr = aiosocks.Socks5Addr('localhost')
    auth = aiosocks.Socks5Auth('usr', 'pwd')
    dst = ('python.org', 80)

    transp, proto = mock.Mock(), mock.Mock()
    reader, writer = mock.Mock(), mock.Mock()

    proto.app_protocol.reader, proto.app_protocol.writer = reader, writer

    loop_mock = mock.Mock()
    loop_mock.create_connection = make_mocked_coro((transp, proto))

    with mock.patch('aiosocks.asyncio.Future') as future_mock:
        future_mock.side_effect = make_mocked_coro(True)
        r, w = await aiosocks.open_connection(addr, auth, dst, loop=loop_mock)

    assert reader is r
    assert writer is w
