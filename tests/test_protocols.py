import asyncio
import aiosocks
import pytest
import socket
import ssl as ssllib
from unittest import mock
from asyncio import coroutine as coro, sslproto
from aiohttp.test_utils import make_mocked_coro
import aiosocks.constants as c
from aiosocks.protocols import BaseSocksProtocol


def make_base(loop, *, dst=None, waiter=None, ap_factory=None, ssl=None):
    dst = dst or ('python.org', 80)

    proto = BaseSocksProtocol(None, None, dst=dst, ssl=ssl,
                              loop=loop, waiter=waiter,
                              app_protocol_factory=ap_factory)
    return proto


def make_socks4(loop, *, addr=None, auth=None, rr=True, dst=None, r=b'',
                ap_factory=None, whiter=None):
    addr = addr or aiosocks.Socks4Addr('localhost', 1080)
    auth = auth or aiosocks.Socks4Auth('user')
    dst = dst or ('python.org', 80)

    proto = aiosocks.Socks4Protocol(
        proxy=addr, proxy_auth=auth, dst=dst, remote_resolve=rr,
        loop=loop, app_protocol_factory=ap_factory, waiter=whiter)
    proto._stream_writer = mock.Mock()
    proto.read_response = mock.Mock(
        side_effect=coro(mock.Mock(return_value=r)))
    proto._get_dst_addr = mock.Mock(
        side_effect=coro(mock.Mock(return_value=(socket.AF_INET, '127.0.0.1')))
    )
    return proto


def make_socks5(loop, *, addr=None, auth=None, rr=True, dst=None, r=None,
                ap_factory=None, whiter=None):
    addr = addr or aiosocks.Socks5Addr('localhost', 1080)
    auth = auth or aiosocks.Socks5Auth('user', 'pwd')
    dst = dst or ('python.org', 80)

    proto = aiosocks.Socks5Protocol(
        proxy=addr, proxy_auth=auth, dst=dst, remote_resolve=rr,
        loop=loop, app_protocol_factory=ap_factory, waiter=whiter)
    proto._stream_writer = mock.Mock()
    proto._stream_writer.drain = make_mocked_coro(True)

    if not isinstance(r, (list, tuple)):
        proto.read_response = mock.Mock(
            side_effect=coro(mock.Mock(return_value=r)))
    else:
        proto.read_response = mock.Mock(
            side_effect=coro(mock.Mock(side_effect=r)))

    proto._get_dst_addr = mock.Mock(
        side_effect=coro(mock.Mock(return_value=(socket.AF_INET, '127.0.0.1')))
    )
    return proto


def test_base_ctor(loop):
    with pytest.raises(ValueError):
        BaseSocksProtocol(None, None, None, loop=loop,
                          waiter=None, app_protocol_factory=None)

    with pytest.raises(ValueError):
        BaseSocksProtocol(None, None, 123, loop=loop,
                          waiter=None, app_protocol_factory=None)

    with pytest.raises(ValueError):
        BaseSocksProtocol(None, None, ('python.org',), loop=loop,
                          waiter=None, app_protocol_factory=None)


def test_base_write_request(loop):
    proto = make_base(loop)
    proto._stream_writer = mock.Mock()

    proto.write_request([b'\x00', b'\x01\x02', 0x03])
    proto._stream_writer.write.assert_called_with(b'\x00\x01\x02\x03')

    with pytest.raises(ValueError):
        proto.write_request(['\x00'])


async def test_base_negotiate_os_error(loop):
    waiter = asyncio.Future(loop=loop)
    proto = make_base(loop, waiter=waiter)
    proto.socks_request = make_mocked_coro(raise_exception=OSError('test'))
    await proto.negotiate(None, None)

    with pytest.raises(OSError) as ct:
        await waiter
    assert 'test' in str(ct.value)


async def test_base_negotiate_socks_err(loop):
    waiter = asyncio.Future(loop=loop)
    proto = make_base(loop, waiter=waiter)
    proto.socks_request = make_mocked_coro(
        raise_exception=aiosocks.SocksError('test'))
    await proto.negotiate(None, None)

    with pytest.raises(aiosocks.SocksError) as ct:
        await waiter
    assert 'Can not connect to' in str(ct.value)


async def test_base_negotiate_without_app_proto(loop):
    waiter = asyncio.Future(loop=loop)
    proto = make_base(loop, waiter=waiter)
    proto.socks_request = make_mocked_coro((None, None))
    proto._transport = True

    await proto.negotiate(None, None)
    await waiter
    assert waiter.done()


async def test_base_negotiate_with_app_proto(loop):
    waiter = asyncio.Future(loop=loop)
    proto = make_base(loop, waiter=waiter,
                      ap_factory=lambda: asyncio.Protocol())
    proto.socks_request = make_mocked_coro((None, None))

    await proto.negotiate(None, None)
    await waiter
    assert waiter.done()


def test_base_connection_lost():
    loop_mock = mock.Mock()
    app_proto = mock.Mock()

    proto = make_base(loop_mock, ap_factory=lambda: app_proto)

    # negotiate not completed
    proto._negotiate_done = False
    proto.connection_lost(True)
    assert not loop_mock.call_soon.called

    # negotiate successfully competed
    loop_mock.reset_mock()
    proto._negotiate_done = True
    proto.connection_lost(True)
    assert loop_mock.call_soon.called

    # don't call connect_lost, if app_protocol == self
    # otherwise recursion
    loop_mock.reset_mock()
    proto = make_base(loop_mock, ap_factory=None)
    proto._negotiate_done = True
    proto.connection_lost(True)
    assert not loop_mock.call_soon.called


def test_base_pause_writing():
    loop_mock = mock.Mock()
    app_proto = mock.Mock()

    proto = make_base(loop_mock, ap_factory=lambda: app_proto)

    # negotiate not completed
    proto._negotiate_done = False
    proto.pause_writing()
    assert not proto._app_protocol.pause_writing.called

    # negotiate successfully competed
    app_proto.reset_mock()
    proto._negotiate_done = True
    proto.pause_writing()
    assert proto._app_protocol.pause_writing.called

    # don't call pause_writing, if app_protocol == self
    # otherwise recursion
    app_proto.reset_mock()
    proto = make_base(loop_mock)
    proto._negotiate_done = True
    proto.pause_writing()


def test_base_resume_writing():
    loop_mock = mock.Mock()
    app_proto = mock.Mock()

    proto = make_base(loop_mock, ap_factory=lambda: app_proto)

    # negotiate not completed
    proto._negotiate_done = False
    # negotiate not completed
    with pytest.raises(AssertionError):
        proto.resume_writing()
    assert not proto._app_protocol.resume_writing.called

    # negotiate successfully competed
    loop_mock.reset_mock()
    proto._negotiate_done = True
    proto.resume_writing()
    assert proto._app_protocol.resume_writing.called

    # don't call resume_writing, if app_protocol == self
    # otherwise recursion
    loop_mock.reset_mock()
    proto = make_base(loop_mock)
    proto._negotiate_done = True
    with pytest.raises(AssertionError):
        proto.resume_writing()


def test_base_data_received():
    loop_mock = mock.Mock()
    app_proto = mock.Mock()

    proto = make_base(loop_mock, ap_factory=lambda: app_proto)

    # negotiate not completed
    proto._negotiate_done = False
    proto.data_received(b'123')
    assert not proto._app_protocol.data_received.called

    # negotiate successfully competed
    app_proto.reset_mock()
    proto._negotiate_done = True
    proto.data_received(b'123')
    assert proto._app_protocol.data_received.called

    # don't call data_received, if app_protocol == self
    # otherwise recursion
    loop_mock.reset_mock()
    proto = make_base(loop_mock)
    proto._negotiate_done = True
    proto.data_received(b'123')


def test_base_eof_received():
    loop_mock = mock.Mock()
    app_proto = mock.Mock()

    proto = make_base(loop_mock, ap_factory=lambda: app_proto)

    # negotiate not completed
    proto._negotiate_done = False
    proto.eof_received()
    assert not proto._app_protocol.eof_received.called

    # negotiate successfully competed
    app_proto.reset_mock()
    proto._negotiate_done = True
    proto.eof_received()
    assert proto._app_protocol.eof_received.called

    # don't call pause_writing, if app_protocol == self
    # otherwise recursion
    app_proto.reset_mock()
    proto = make_base(loop_mock)
    proto._negotiate_done = True
    proto.eof_received()


async def test_base_make_ssl_proto():
    loop_mock = mock.Mock()
    app_proto = mock.Mock()

    ssl_context = ssllib.create_default_context()
    proto = make_base(loop_mock,
                      ap_factory=lambda: app_proto, ssl=ssl_context)
    proto.socks_request = make_mocked_coro((None, None))
    proto._transport = mock.Mock()
    await proto.negotiate(None, None)

    assert isinstance(proto._transport, sslproto._SSLProtocolTransport)


async def test_base_func_negotiate_cb_call():
    loop_mock = mock.Mock()
    waiter = mock.Mock()

    proto = make_base(loop_mock, waiter=waiter)
    proto.socks_request = make_mocked_coro((None, None))
    proto._negotiate_done_cb = mock.Mock()

    with mock.patch('aiosocks.protocols.asyncio.Task') as task_mock:
        await proto.negotiate(None, None)
        assert proto._negotiate_done_cb.called
        assert not task_mock.called


async def test_base_coro_negotiate_cb_call():
    loop_mock = mock.Mock()
    waiter = mock.Mock()

    proto = make_base(loop_mock, waiter=waiter)
    proto.socks_request = make_mocked_coro((None, None))
    proto._negotiate_done_cb = make_mocked_coro(None)

    await (await proto.negotiate(None, None))
    assert proto._negotiate_done_cb.called


async def test_base_reader_limit(loop):
    proto = BaseSocksProtocol(None, None, ('python.org', 80),
                              None, None, reader_limit=10, loop=loop)
    assert proto.reader._limit == 10

    proto = BaseSocksProtocol(None, None, ('python.org', 80),
                              None, None, reader_limit=15, loop=loop)
    assert proto.reader._limit == 15


async def test_base_incomplete_error(loop):
    proto = BaseSocksProtocol(None, None, ('python.org', 80),
                              None, None, reader_limit=10, loop=loop)
    proto._stream_reader.readexactly = make_mocked_coro(
        raise_exception=asyncio.IncompleteReadError(b'part', 5))
    with pytest.raises(aiosocks.InvalidServerReply):
        await proto.read_response(4)


def test_socks4_ctor(loop):
    addr = aiosocks.Socks4Addr('localhost', 1080)
    auth = aiosocks.Socks4Auth('user')
    dst = ('python.org', 80)

    with pytest.raises(ValueError):
        aiosocks.Socks4Protocol(None, None, dst, loop=loop,
                                waiter=None, app_protocol_factory=None)

    with pytest.raises(ValueError):
        aiosocks.Socks4Protocol(None, auth, dst, loop=loop,
                                waiter=None, app_protocol_factory=None)

    with pytest.raises(ValueError):
        aiosocks.Socks4Protocol(aiosocks.Socks5Addr('host'), auth, dst,
                                loop=loop, waiter=None,
                                app_protocol_factory=None)

    with pytest.raises(ValueError):
        aiosocks.Socks4Protocol(addr, aiosocks.Socks5Auth('l', 'p'), dst,
                                loop=loop, waiter=None,
                                app_protocol_factory=None)

    aiosocks.Socks4Protocol(addr, None, dst, loop=loop,
                            waiter=None, app_protocol_factory=None)
    aiosocks.Socks4Protocol(addr, auth, dst, loop=loop,
                            waiter=None, app_protocol_factory=None)


async def test_socks4_dst_domain_with_remote_resolve(loop):
    proto = make_socks4(loop, dst=('python.org', 80),
                        r=b'\x00\x5a\x00P\x7f\x00\x00\x01')

    await proto.socks_request(c.SOCKS_CMD_CONNECT)
    proto._stream_writer.write.assert_called_with(
        b'\x04\x01\x00P\x00\x00\x00\x01user\x00python.org\x00')


async def test_socks4_dst_domain_with_local_resolve(loop):
    proto = make_socks4(loop, dst=('python.org', 80),
                        rr=False, r=b'\x00\x5a\x00P\x7f\x00\x00\x01')

    await proto.socks_request(c.SOCKS_CMD_CONNECT)
    proto._stream_writer.write.assert_called_with(
        b'\x04\x01\x00P\x7f\x00\x00\x01user\x00')


async def test_socks4_dst_ip_with_remote_resolve(loop):
    proto = make_socks4(loop, dst=('127.0.0.1', 8800),
                        r=b'\x00\x5a\x00P\x7f\x00\x00\x01')

    await proto.socks_request(c.SOCKS_CMD_CONNECT)
    proto._stream_writer.write.assert_called_with(
        b'\x04\x01"`\x7f\x00\x00\x01user\x00')


async def test_socks4_dst_ip_with_locale_resolve(loop):
    proto = make_socks4(loop, dst=('127.0.0.1', 8800),
                        rr=False, r=b'\x00\x5a\x00P\x7f\x00\x00\x01')

    await proto.socks_request(c.SOCKS_CMD_CONNECT)
    proto._stream_writer.write.assert_called_with(
        b'\x04\x01"`\x7f\x00\x00\x01user\x00')


async def test_socks4_dst_domain_without_user(loop):
    proto = make_socks4(loop, auth=aiosocks.Socks4Auth(''),
                        dst=('python.org', 80),
                        r=b'\x00\x5a\x00P\x7f\x00\x00\x01')

    await proto.socks_request(c.SOCKS_CMD_CONNECT)
    proto._stream_writer.write.assert_called_with(
        b'\x04\x01\x00P\x00\x00\x00\x01\x00python.org\x00')


async def test_socks4_dst_ip_without_user(loop):
    proto = make_socks4(loop, auth=aiosocks.Socks4Auth(''),
                        dst=('127.0.0.1', 8800),
                        r=b'\x00\x5a\x00P\x7f\x00\x00\x01')

    await proto.socks_request(c.SOCKS_CMD_CONNECT)
    proto._stream_writer.write.assert_called_with(
        b'\x04\x01"`\x7f\x00\x00\x01\x00')


async def test_socks4_valid_resp_handling(loop):
    proto = make_socks4(loop, r=b'\x00\x5a\x00P\x7f\x00\x00\x01')

    r = await proto.socks_request(c.SOCKS_CMD_CONNECT)
    assert r == (('python.org', 80), ('127.0.0.1', 80))


async def test_socks4_invalid_reply_resp_handling(loop):
    proto = make_socks4(loop, r=b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF')

    with pytest.raises(aiosocks.InvalidServerReply):
        await proto.socks_request(c.SOCKS_CMD_CONNECT)


async def test_socks_err_resp_handling(loop):
    proto = make_socks4(loop, r=b'\x00\x5b\x00P\x7f\x00\x00\x01')

    with pytest.raises(aiosocks.SocksError) as cm:
        await proto.socks_request(c.SOCKS_CMD_CONNECT)
    assert '0x5b' in str(cm.value)


async def test_socks4_unknown_err_resp_handling(loop):
    proto = make_socks4(loop, r=b'\x00\x5e\x00P\x7f\x00\x00\x01')

    with pytest.raises(aiosocks.SocksError) as cm:
        await proto.socks_request(c.SOCKS_CMD_CONNECT)
    assert 'Unknown error' in str(cm.value)


def test_socks5_ctor(loop):
    addr = aiosocks.Socks5Addr('localhost', 1080)
    auth = aiosocks.Socks5Auth('user', 'pwd')
    dst = ('python.org', 80)

    with pytest.raises(ValueError):
        aiosocks.Socks5Protocol(None, None, dst, loop=loop,
                                waiter=None, app_protocol_factory=None)

    with pytest.raises(ValueError):
        aiosocks.Socks5Protocol(None, auth, dst, loop=loop,
                                waiter=None, app_protocol_factory=None)

    with pytest.raises(ValueError):
        aiosocks.Socks5Protocol(aiosocks.Socks4Addr('host'),
                                auth, dst, loop=loop,
                                waiter=None, app_protocol_factory=None)

    with pytest.raises(ValueError):
        aiosocks.Socks5Protocol(addr, aiosocks.Socks4Auth('l'),
                                dst, loop=loop,
                                waiter=None, app_protocol_factory=None)

    aiosocks.Socks5Protocol(addr, None, dst, loop=loop,
                            waiter=None, app_protocol_factory=None)
    aiosocks.Socks5Protocol(addr, auth, dst, loop=loop,
                            waiter=None, app_protocol_factory=None)


async def test_socks5_auth_inv_srv_ver(loop):
    proto = make_socks5(loop, r=b'\x00\x00')

    with pytest.raises(aiosocks.InvalidServerVersion):
        await proto.authenticate()


async def test_socks5_auth_no_acceptable_auth_methods(loop):
    proto = make_socks5(loop, r=b'\x05\xFF')

    with pytest.raises(aiosocks.NoAcceptableAuthMethods):
        await proto.authenticate()


async def test_socks5_auth_unsupported_auth_method(loop):
    proto = make_socks5(loop, r=b'\x05\xF0')

    with pytest.raises(aiosocks.InvalidServerReply):
        await proto.authenticate()


async def test_socks5_auth_usr_pwd_granted(loop):
    proto = make_socks5(loop, r=(b'\x05\x02', b'\x01\x00',))
    await proto.authenticate()

    proto._stream_writer.write.assert_has_calls([
        mock.call(b'\x05\x02\x00\x02'),
        mock.call(b'\x01\x04user\x03pwd')
    ])


async def test_socks5_auth_invalid_reply(loop):
    proto = make_socks5(loop, r=(b'\x05\x02', b'\x00\x00',))

    with pytest.raises(aiosocks.InvalidServerReply):
        await proto.authenticate()


async def test_socks5_auth_access_denied(loop):
    proto = make_socks5(loop, r=(b'\x05\x02', b'\x01\x01',))

    with pytest.raises(aiosocks.LoginAuthenticationFailed):
        await proto.authenticate()


async def test_socks5_auth_anonymous_granted(loop):
    proto = make_socks5(loop, r=b'\x05\x00')
    await proto.authenticate()


async def test_socks5_build_dst_addr_ipv4(loop):
    proto = make_socks5(loop)
    dst_req, resolved = await proto.build_dst_address('127.0.0.1', 80)

    assert dst_req == [0x01, b'\x7f\x00\x00\x01', b'\x00P']
    assert resolved == ('127.0.0.1', 80)


async def test_socks5_build_dst_addr_ipv6(loop):
    proto = make_socks5(loop)
    dst_req, resolved = await proto.build_dst_address(
        '2001:0db8:11a3:09d7:1f34:8a2e:07a0:765d', 80)

    assert dst_req == [
        0x04, b' \x01\r\xb8\x11\xa3\t\xd7\x1f4\x8a.\x07\xa0v]', b'\x00P']
    assert resolved == ('2001:0db8:11a3:09d7:1f34:8a2e:07a0:765d', 80)


async def test_socks5_build_dst_addr_domain_with_remote_resolve(loop):
    proto = make_socks5(loop)
    dst_req, resolved = await proto.build_dst_address('python.org', 80)

    assert dst_req == [0x03, b'\n', b'python.org', b'\x00P']
    assert resolved == ('python.org', 80)


async def test_socks5_build_dst_addr_domain_with_locale_resolve(loop):
    proto = make_socks5(loop, rr=False)
    dst_req, resolved = await proto.build_dst_address('python.org', 80)

    assert dst_req == [0x01, b'\x7f\x00\x00\x01', b'\x00P']
    assert resolved == ('127.0.0.1', 80)


async def test_socks5_rd_addr_ipv4(loop):
    proto = make_socks5(loop, r=[b'\x01', b'\x7f\x00\x00\x01', b'\x00P'])
    r = await proto.read_address()

    assert r == ('127.0.0.1', 80)


async def test_socks5_rd_addr_ipv6(loop):
    resp = [
        b'\x04',
        b' \x01\r\xb8\x11\xa3\t\xd7\x1f4\x8a.\x07\xa0v]',
        b'\x00P'
    ]
    proto = make_socks5(loop, r=resp)
    r = await proto.read_address()

    assert r == ('2001:db8:11a3:9d7:1f34:8a2e:7a0:765d', 80)


async def test_socks5_rd_addr_domain(loop):
    proto = make_socks5(loop, r=[b'\x03', b'\n', b'python.org', b'\x00P'])
    r = await proto.read_address()

    assert r == (b'python.org', 80)


async def test_socks5_socks_req_inv_ver(loop):
    proto = make_socks5(loop, r=[b'\x05\x00', b'\x04\x00\x00'])

    with pytest.raises(aiosocks.InvalidServerVersion):
        await proto.socks_request(c.SOCKS_CMD_CONNECT)


async def test_socks5_socks_req_socks_srv_err(loop):
    proto = make_socks5(loop, r=[b'\x05\x00', b'\x05\x02\x00'])

    with pytest.raises(aiosocks.SocksError) as ct:
        await proto.socks_request(c.SOCKS_CMD_CONNECT)
    assert 'Connection not allowed by ruleset' in str(ct.value)


async def test_socks5_socks_req_unknown_err(loop):
    proto = make_socks5(loop, r=[b'\x05\x00', b'\x05\xFF\x00'])

    with pytest.raises(aiosocks.SocksError) as ct:
        await proto.socks_request(c.SOCKS_CMD_CONNECT)
    assert 'Unknown error' in str(ct.value)


async def test_socks_req_cmd_granted(loop):
    # cmd granted
    resp = [b'\x05\x00',
            b'\x05\x00\x00',
            b'\x01', b'\x7f\x00\x00\x01',
            b'\x00P']
    proto = make_socks5(loop, r=resp)
    r = await proto.socks_request(c.SOCKS_CMD_CONNECT)

    assert r == (('python.org', 80), ('127.0.0.1', 80))
    proto._stream_writer.write.assert_has_calls([
        mock.call(b'\x05\x02\x00\x02'),
        mock.call(b'\x05\x01\x00\x03\npython.org\x00P')
    ])
