import asyncio
import aiosocks
import unittest
import socket
from unittest import mock
from asyncio import coroutine as coro
import aiosocks.constants as c
from aiosocks.protocols import BaseSocksProtocol

try:
    from asyncio import ensure_future
except ImportError:
    ensure_future = asyncio.async


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
    proto._transport = mock.Mock()
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
    proto._transport = mock.Mock()

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


class TestBaseSocksProtocol(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)

    def tearDown(self):
        self.loop.close()

    def test_init(self):
        with self.assertRaises(ValueError):
            BaseSocksProtocol(None, None, None, loop=self.loop,
                              waiter=None, app_protocol_factory=None)

        with self.assertRaises(ValueError):
            BaseSocksProtocol(None, None, 123, loop=self.loop,
                              waiter=None, app_protocol_factory=None)

        with self.assertRaises(ValueError):
            BaseSocksProtocol(None, None, ('python.org',), loop=self.loop,
                              waiter=None, app_protocol_factory=None)

    def test_write_request(self):
        proto = make_base(self.loop)
        proto._transport = mock.Mock()

        proto.write_request([b'\x00', b'\x01\x02', 0x03])
        proto._transport.write.assert_called_with(b'\x00\x01\x02\x03')

        with self.assertRaises(ValueError):
            proto.write_request(['\x00'])

    @mock.patch('aiosocks.protocols.ensure_future')
    def test_connection_made_os_error(self, ef_mock):
        os_err_fut = asyncio.Future(loop=self.loop)
        ef_mock.return_value = os_err_fut

        waiter = asyncio.Future(loop=self.loop)
        proto = make_base(self.loop, waiter=waiter)
        proto.connection_made(mock.Mock())

        self.assertIs(proto._negotiate_fut, os_err_fut)

        with self.assertRaises(OSError):
            os_err_fut.set_exception(OSError('test'))
            self.loop.run_until_complete(os_err_fut)
        self.assertIn('test', str(waiter.exception()))

    @mock.patch('aiosocks.protocols.ensure_future')
    def test_connection_made_socks_err(self, ef_mock):
        socks_err_fut = asyncio.Future(loop=self.loop)
        ef_mock.return_value = socks_err_fut

        waiter = asyncio.Future(loop=self.loop)
        proto = make_base(self.loop, waiter=waiter)
        proto.connection_made(mock.Mock())

        self.assertIs(proto._negotiate_fut, socks_err_fut)

        with self.assertRaises(aiosocks.SocksError):
            socks_err_fut.set_exception(aiosocks.SocksError('test'))
            self.loop.run_until_complete(socks_err_fut)
        self.assertIn('Can not connect to', str(waiter.exception()))

    @mock.patch('aiosocks.protocols.ensure_future')
    def test_connection_made_without_app_proto(self, ef_mock):
        success_fut = asyncio.Future(loop=self.loop)
        ef_mock.return_value = success_fut

        waiter = asyncio.Future(loop=self.loop)
        proto = make_base(self.loop, waiter=waiter)
        proto.connection_made(mock.Mock())

        self.assertIs(proto._negotiate_fut, success_fut)

        success_fut.set_result(True)
        self.loop.run_until_complete(success_fut)
        self.assertTrue(waiter.done())

    @mock.patch('aiosocks.protocols.ensure_future')
    def test_connection_made_with_app_proto(self, ef_mock):
        success_fut = asyncio.Future(loop=self.loop)
        ef_mock.return_value = success_fut

        waiter = asyncio.Future(loop=self.loop)
        proto = make_base(self.loop, waiter=waiter,
                          ap_factory=lambda: asyncio.Protocol())
        proto.connection_made(mock.Mock())

        self.assertIs(proto._negotiate_fut, success_fut)

        success_fut.set_result(True)
        self.loop.run_until_complete(success_fut)
        self.assertTrue(waiter.done())

    @mock.patch('aiosocks.protocols.ensure_future')
    def test_connection_lost(self, ef_mock):
        negotiate_fut = asyncio.Future(loop=self.loop)
        ef_mock.return_value = negotiate_fut
        app_proto = mock.Mock()

        loop_mock = mock.Mock()

        proto = make_base(loop_mock, ap_factory=lambda: app_proto)
        proto.connection_made(mock.Mock())

        # negotiate not completed
        proto.connection_lost(True)
        self.assertFalse(loop_mock.call_soon.called)

        # negotiate successfully competed
        negotiate_fut.set_result(True)
        proto.connection_lost(True)
        self.assertTrue(loop_mock.call_soon.called)

        # negotiate failed
        negotiate_fut = asyncio.Future(loop=self.loop)
        ef_mock.return_value = negotiate_fut

        proto = make_base(loop_mock, ap_factory=lambda: app_proto)
        proto.connection_made(mock.Mock())

        negotiate_fut.set_exception(Exception())
        proto.connection_lost(True)
        self.assertTrue(loop_mock.call_soon.called)

    @mock.patch('aiosocks.protocols.ensure_future')
    def test_pause_writing(self, ef_mock):
        negotiate_fut = asyncio.Future(loop=self.loop)
        ef_mock.return_value = negotiate_fut
        app_proto = mock.Mock()

        loop_mock = mock.Mock()

        proto = make_base(loop_mock, ap_factory=lambda: app_proto)
        proto.connection_made(mock.Mock())

        # negotiate not completed
        proto.pause_writing()
        self.assertFalse(app_proto.pause_writing.called)

        # negotiate successfully competed
        negotiate_fut.set_result(True)
        proto.pause_writing()
        self.assertTrue(app_proto.pause_writing.called)

    @mock.patch('aiosocks.protocols.ensure_future')
    def test_resume_writing(self, ef_mock):
        negotiate_fut = asyncio.Future(loop=self.loop)
        ef_mock.return_value = negotiate_fut
        app_proto = mock.Mock()

        loop_mock = mock.Mock()

        proto = make_base(loop_mock, ap_factory=lambda: app_proto)
        proto.connection_made(mock.Mock())

        # negotiate not completed
        with self.assertRaises(AssertionError):
            proto.resume_writing()

        # negotiate fail
        negotiate_fut.set_exception(Exception())
        proto.resume_writing()
        self.assertTrue(app_proto.resume_writing.called)

    @mock.patch('aiosocks.protocols.ensure_future')
    def test_data_received(self, ef_mock):
        negotiate_fut = asyncio.Future(loop=self.loop)
        ef_mock.return_value = negotiate_fut
        app_proto = mock.Mock()

        loop_mock = mock.Mock()

        proto = make_base(loop_mock, ap_factory=lambda: app_proto)
        proto.connection_made(mock.Mock())

        # negotiate not completed
        proto.data_received(b'123')
        self.assertFalse(app_proto.data_received.called)

        # negotiate successfully competed
        negotiate_fut.set_result(True)
        proto.data_received(b'123')
        self.assertTrue(app_proto.data_received.called)

    @mock.patch('aiosocks.protocols.ensure_future')
    def test_eof_received(self, ef_mock):
        negotiate_fut = asyncio.Future(loop=self.loop)
        ef_mock.return_value = negotiate_fut
        app_proto = mock.Mock()

        loop_mock = mock.Mock()

        proto = make_base(loop_mock, ap_factory=lambda: app_proto)
        proto.connection_made(mock.Mock())

        # negotiate not completed
        proto.eof_received()
        self.assertFalse(app_proto.eof_received.called)

        # negotiate successfully competed
        negotiate_fut.set_result(True)
        proto.eof_received()
        self.assertTrue(app_proto.eof_received.called)


class TestSocks4Protocol(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)

    def tearDown(self):
        self.loop.close()

    def test_init(self):
        addr = aiosocks.Socks4Addr('localhost', 1080)
        auth = aiosocks.Socks4Auth('user')
        dst = ('python.org', 80)

        with self.assertRaises(ValueError):
            aiosocks.Socks4Protocol(None, None, dst, loop=self.loop,
                                    waiter=None, app_protocol_factory=None)

        with self.assertRaises(ValueError):
            aiosocks.Socks4Protocol(None, auth, dst, loop=self.loop,
                                    waiter=None, app_protocol_factory=None)

        with self.assertRaises(ValueError):
            aiosocks.Socks4Protocol(aiosocks.Socks5Addr('host'), auth, dst,
                                    loop=self.loop, waiter=None,
                                    app_protocol_factory=None)

        with self.assertRaises(ValueError):
            aiosocks.Socks4Protocol(addr, aiosocks.Socks5Auth('l', 'p'), dst,
                                    loop=self.loop, waiter=None,
                                    app_protocol_factory=None)

        aiosocks.Socks4Protocol(addr, None, dst, loop=self.loop,
                                waiter=None, app_protocol_factory=None)
        aiosocks.Socks4Protocol(addr, auth, dst, loop=self.loop,
                                waiter=None, app_protocol_factory=None)

    def test_request_building(self):
        resp = b'\x00\x5a\x00P\x7f\x00\x00\x01'

        # dst = domain, remote resolve = true
        proto = make_socks4(self.loop, dst=('python.org', 80), r=resp)

        req = proto.socks_request(c.SOCKS_CMD_CONNECT)
        self.loop.run_until_complete(req)

        proto._transport.write.assert_called_with(
            b'\x04\x01\x00P\x00\x00\x00\x01user\x00python.org\x00'
        )

        # dst = domain, remote resolve = false
        proto = make_socks4(self.loop, dst=('python.org', 80),
                            rr=False, r=resp)

        req = proto.socks_request(c.SOCKS_CMD_CONNECT)
        self.loop.run_until_complete(req)

        proto._transport.write.assert_called_with(
            b'\x04\x01\x00P\x7f\x00\x00\x01user\x00'
        )

        # dst = ip, remote resolve = true
        proto = make_socks4(self.loop, dst=('127.0.0.1', 8800), r=resp)
        req = proto.socks_request(c.SOCKS_CMD_CONNECT)
        self.loop.run_until_complete(req)

        proto._transport.write.assert_called_with(
            b'\x04\x01"`\x7f\x00\x00\x01user\x00'
        )

        # dst = ip, remote resolve = false
        proto = make_socks4(self.loop, dst=('127.0.0.1', 8800),
                            rr=False, r=resp)
        req = proto.socks_request(c.SOCKS_CMD_CONNECT)
        self.loop.run_until_complete(req)

        proto._transport.write.assert_called_with(
            b'\x04\x01"`\x7f\x00\x00\x01user\x00'
        )

        # dst = domain, without user
        proto = make_socks4(self.loop, auth=aiosocks.Socks4Auth(''),
                            dst=('python.org', 80), r=resp)
        req = proto.socks_request(c.SOCKS_CMD_CONNECT)
        self.loop.run_until_complete(req)

        proto._transport.write.assert_called_with(
            b'\x04\x01\x00P\x00\x00\x00\x01\x00python.org\x00'
        )

        # dst = ip, without user
        proto = make_socks4(self.loop, auth=aiosocks.Socks4Auth(''),
                            dst=('127.0.0.1', 8800), r=resp)
        req = proto.socks_request(c.SOCKS_CMD_CONNECT)
        self.loop.run_until_complete(req)

        proto._transport.write.assert_called_with(
            b'\x04\x01"`\x7f\x00\x00\x01\x00'
        )

    def test_response_handling(self):
        valid_resp = b'\x00\x5a\x00P\x7f\x00\x00\x01'
        invalid_data_resp = b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF'
        socks_err_resp = b'\x00\x5b\x00P\x7f\x00\x00\x01'
        socks_err_unk_resp = b'\x00\x5e\x00P\x7f\x00\x00\x01'

        # valid result
        proto = make_socks4(self.loop, r=valid_resp)
        req = ensure_future(
            proto.socks_request(c.SOCKS_CMD_CONNECT), loop=self.loop)
        self.loop.run_until_complete(req)

        self.assertEqual(req.result(), (('python.org', 80), ('127.0.0.1', 80)))

        # invalid server reply
        proto = make_socks4(self.loop, r=invalid_data_resp)
        req = proto.socks_request(c.SOCKS_CMD_CONNECT)

        with self.assertRaises(aiosocks.InvalidServerReply):
            self.loop.run_until_complete(req)

        # socks server sent error
        proto = make_socks4(self.loop, r=socks_err_resp)
        req = proto.socks_request(c.SOCKS_CMD_CONNECT)

        with self.assertRaises(aiosocks.SocksError) as cm:
            self.loop.run_until_complete(req)

        self.assertTrue('0x5b' in str(cm.exception))

        # socks server send unknown error
        proto = make_socks4(self.loop, r=socks_err_unk_resp)
        req = proto.socks_request(c.SOCKS_CMD_CONNECT)

        with self.assertRaises(aiosocks.SocksError) as cm:
            self.loop.run_until_complete(req)

        self.assertTrue('Unknown error' in str(cm.exception))


class TestSocks5Protocol(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)

    def tearDown(self):
        self.loop.close()

    def test_init(self):
        addr = aiosocks.Socks5Addr('localhost', 1080)
        auth = aiosocks.Socks5Auth('user', 'pwd')
        dst = ('python.org', 80)

        with self.assertRaises(ValueError):
            aiosocks.Socks5Protocol(None, None, dst, loop=self.loop,
                                    waiter=None, app_protocol_factory=None)

        with self.assertRaises(ValueError):
            aiosocks.Socks5Protocol(None, auth, dst, loop=self.loop,
                                    waiter=None, app_protocol_factory=None)

        with self.assertRaises(ValueError):
            aiosocks.Socks5Protocol(aiosocks.Socks4Addr('host'),
                                    auth, dst, loop=self.loop,
                                    waiter=None, app_protocol_factory=None)

        with self.assertRaises(ValueError):
            aiosocks.Socks5Protocol(addr, aiosocks.Socks4Auth('l'),
                                    dst, loop=self.loop,
                                    waiter=None, app_protocol_factory=None)

        aiosocks.Socks5Protocol(addr, None, dst, loop=self.loop,
                                waiter=None, app_protocol_factory=None)
        aiosocks.Socks5Protocol(addr, auth, dst, loop=self.loop,
                                waiter=None, app_protocol_factory=None)

    def test_authenticate(self):
        # invalid server version
        proto = make_socks5(self.loop, r=b'\x00\x00')
        req = proto.authenticate()

        with self.assertRaises(aiosocks.InvalidServerVersion):
            self.loop.run_until_complete(req)

        # anonymous auth granted
        proto = make_socks5(self.loop, r=b'\x05\x00')
        req = proto.authenticate()
        self.loop.run_until_complete(req)

        # no acceptable auth methods
        proto = make_socks5(self.loop, r=b'\x05\xFF')
        req = proto.authenticate()
        with self.assertRaises(aiosocks.NoAcceptableAuthMethods):
            self.loop.run_until_complete(req)

        # unsupported auth method
        proto = make_socks5(self.loop, r=b'\x05\xF0')
        req = proto.authenticate()
        with self.assertRaises(aiosocks.InvalidServerReply):
            self.loop.run_until_complete(req)

        # auth: username, pwd
        # access granted
        proto = make_socks5(self.loop, r=(b'\x05\x02', b'\x01\x00',))
        req = proto.authenticate()
        self.loop.run_until_complete(req)
        proto._transport.write.assert_has_calls([
            mock.call(b'\x05\x02\x00\x02'),
            mock.call(b'\x01\x04user\x03pwd')
        ])

        # invalid reply
        proto = make_socks5(self.loop, r=(b'\x05\x02', b'\x00\x00',))
        req = proto.authenticate()
        with self.assertRaises(aiosocks.InvalidServerReply):
            self.loop.run_until_complete(req)

        # access denied
        proto = make_socks5(self.loop, r=(b'\x05\x02', b'\x01\x01',))
        req = proto.authenticate()
        with self.assertRaises(aiosocks.LoginAuthenticationFailed):
            self.loop.run_until_complete(req)

    def test_write_address(self):
        # ipv4
        proto = make_socks5(self.loop)
        req = proto.write_address('127.0.0.1', 80)
        self.loop.run_until_complete(req)

        proto._transport.write.assert_called_with(b'\x01\x7f\x00\x00\x01\x00P')

        # ipv6
        proto = make_socks5(self.loop)
        req = proto.write_address(
            '2001:0db8:11a3:09d7:1f34:8a2e:07a0:765d', 80)
        self.loop.run_until_complete(req)

        proto._transport.write.assert_called_with(
            b'\x04 \x01\r\xb8\x11\xa3\t\xd7\x1f4\x8a.\x07\xa0v]\x00P')

        # domain, remote_resolve = true
        proto = make_socks5(self.loop)
        req = proto.write_address('python.org', 80)
        self.loop.run_until_complete(req)

        proto._transport.write.assert_called_with(b'\x03\npython.org\x00P')

        # domain, remote resolve = false
        proto = make_socks5(self.loop, rr=False)
        req = proto.write_address('python.org', 80)
        self.loop.run_until_complete(req)

        proto._transport.write.assert_called_with(b'\x01\x7f\x00\x00\x01\x00P')

    def test_read_address(self):
        # ipv4
        proto = make_socks5(
            self.loop, r=[b'\x01', b'\x7f\x00\x00\x01', b'\x00P'])
        req = ensure_future(proto.read_address(), loop=self.loop)
        self.loop.run_until_complete(req)

        self.assertEqual(req.result(), ('127.0.0.1', 80))

        # ipv6
        resp = [
            b'\x04',
            b' \x01\r\xb8\x11\xa3\t\xd7\x1f4\x8a.\x07\xa0v]',
            b'\x00P'
        ]
        proto = make_socks5(self.loop, r=resp)
        req = ensure_future(proto.read_address(), loop=self.loop)
        self.loop.run_until_complete(req)

        self.assertEqual(
            req.result(), ('2001:db8:11a3:9d7:1f34:8a2e:7a0:765d', 80))

        # domain
        proto = make_socks5(
            self.loop, r=[b'\x03', b'\n', b'python.org', b'\x00P'])
        req = ensure_future(proto.read_address(), loop=self.loop)
        self.loop.run_until_complete(req)

        self.assertEqual(req.result(), (b'python.org', 80))

    def test_socks_request(self):
        # invalid version
        proto = make_socks5(self.loop, r=[b'\x05\x00', b'\x04\x00\x00'])
        req = proto.socks_request(c.SOCKS_CMD_CONNECT)
        with self.assertRaises(aiosocks.InvalidServerVersion):
            self.loop.run_until_complete(req)

        # socks error
        proto = make_socks5(self.loop, r=[b'\x05\x00', b'\x05\x02\x00'])
        req = proto.socks_request(c.SOCKS_CMD_CONNECT)
        with self.assertRaises(aiosocks.SocksError) as ct:
            self.loop.run_until_complete(req)

        self.assertTrue(
            'Connection not allowed by ruleset' in str(ct.exception))

        # socks unknown error
        proto = make_socks5(self.loop, r=[b'\x05\x00', b'\x05\xFF\x00'])
        req = proto.socks_request(c.SOCKS_CMD_CONNECT)
        with self.assertRaises(aiosocks.SocksError) as ct:
            self.loop.run_until_complete(req)

        self.assertTrue('Unknown error' in str(ct.exception))

        # cmd granted
        resp = [b'\x05\x00',
                b'\x05\x00\x00',
                b'\x01', b'\x7f\x00\x00\x01',
                b'\x00P']
        proto = make_socks5(self.loop, r=resp)
        req = ensure_future(proto.socks_request(c.SOCKS_CMD_CONNECT),
                            loop=self.loop)
        self.loop.run_until_complete(req)

        self.assertEqual(req.result(), (('python.org', 80), ('127.0.0.1', 80)))
        proto._transport.write.assert_has_calls([
            mock.call(b'\x05\x02\x00\x02'),
            mock.call(b'\x05\x01\x00'),
            mock.call(b'\x03\npython.org\x00P')
        ])
