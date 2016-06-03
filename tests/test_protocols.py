import asyncio
import aiosocks
import unittest
import socket
import ssl as ssllib
from unittest import mock
from asyncio import coroutine as coro
import aiosocks.constants as c
from aiosocks.protocols import BaseSocksProtocol
from .helpers import fake_coroutine

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
    proto._stream_writer.drain = fake_coroutine(True)

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
        proto._stream_writer = mock.Mock()

        proto.write_request([b'\x00', b'\x01\x02', 0x03])
        proto._stream_writer.write.assert_called_with(b'\x00\x01\x02\x03')

        with self.assertRaises(ValueError):
            proto.write_request(['\x00'])

    def test_negotiate_os_error(self):
        waiter = asyncio.Future(loop=self.loop)
        proto = make_base(self.loop, waiter=waiter)
        proto.socks_request = fake_coroutine(OSError('test'))

        self.loop.run_until_complete(proto.negotiate(None, None))
        self.assertIn('test', str(waiter.exception()))

    def test_negotiate_socks_err(self):
        waiter = asyncio.Future(loop=self.loop)
        proto = make_base(self.loop, waiter=waiter)
        proto.socks_request = fake_coroutine(aiosocks.SocksError('test'))

        self.loop.run_until_complete(proto.negotiate(None, None))
        self.assertIn('Can not connect to', str(waiter.exception()))

    def test_negotiate_without_app_proto(self):
        waiter = asyncio.Future(loop=self.loop)
        proto = make_base(self.loop, waiter=waiter)
        proto.socks_request = fake_coroutine((None, None))
        proto._transport = True

        self.loop.run_until_complete(proto.negotiate(None, None))
        self.assertTrue(waiter.done())

    def test_negotiate_with_app_proto(self):
        waiter = asyncio.Future(loop=self.loop)
        proto = make_base(self.loop, waiter=waiter,
                          ap_factory=lambda: asyncio.Protocol())
        proto.socks_request = fake_coroutine((None, None))

        self.loop.run_until_complete(proto.negotiate(None, None))
        self.assertTrue(waiter.done())

    def test_connection_lost(self):
        loop_mock = mock.Mock()
        app_proto = mock.Mock()

        proto = make_base(loop_mock, ap_factory=lambda: app_proto)

        # negotiate not completed
        proto._negotiate_done = False
        proto.connection_lost(True)
        self.assertFalse(loop_mock.call_soon.called)

        # negotiate successfully competed
        loop_mock.reset_mock()
        proto._negotiate_done = True
        proto.connection_lost(True)
        self.assertTrue(loop_mock.call_soon.called)

        # don't call connect_lost, if app_protocol == self
        # otherwise recursion
        loop_mock.reset_mock()
        proto = make_base(loop_mock, ap_factory=None)
        proto._negotiate_done = True
        proto.connection_lost(True)
        self.assertFalse(loop_mock.call_soon.called)

    def test_pause_writing(self):
        loop_mock = mock.Mock()
        app_proto = mock.Mock()

        proto = make_base(loop_mock, ap_factory=lambda: app_proto)

        # negotiate not completed
        proto._negotiate_done = False
        proto.pause_writing()
        self.assertFalse(proto._app_protocol.pause_writing.called)

        # negotiate successfully competed
        app_proto.reset_mock()
        proto._negotiate_done = True
        proto.pause_writing()
        self.assertTrue(proto._app_protocol.pause_writing.called)

        # don't call pause_writing, if app_protocol == self
        # otherwise recursion
        app_proto.reset_mock()
        proto = make_base(loop_mock)
        proto._negotiate_done = True
        proto.pause_writing()

    def test_resume_writing(self):
        loop_mock = mock.Mock()
        app_proto = mock.Mock()

        proto = make_base(loop_mock, ap_factory=lambda: app_proto)

        # negotiate not completed
        proto._negotiate_done = False
        # negotiate not completed
        with self.assertRaises(AssertionError):
            proto.resume_writing()
        self.assertFalse(proto._app_protocol.resume_writing.called)

        # negotiate successfully competed
        loop_mock.reset_mock()
        proto._negotiate_done = True
        proto.resume_writing()
        self.assertTrue(proto._app_protocol.resume_writing.called)

        # don't call resume_writing, if app_protocol == self
        # otherwise recursion
        loop_mock.reset_mock()
        proto = make_base(loop_mock)
        proto._negotiate_done = True
        with self.assertRaises(AssertionError):
            proto.resume_writing()

    def test_data_received(self):
        loop_mock = mock.Mock()
        app_proto = mock.Mock()

        proto = make_base(loop_mock, ap_factory=lambda: app_proto)

        # negotiate not completed
        proto._negotiate_done = False
        proto.data_received(b'123')
        self.assertFalse(proto._app_protocol.data_received.called)

        # negotiate successfully competed
        app_proto.reset_mock()
        proto._negotiate_done = True
        proto.data_received(b'123')
        self.assertTrue(proto._app_protocol.data_received.called)

        # don't call data_received, if app_protocol == self
        # otherwise recursion
        loop_mock.reset_mock()
        proto = make_base(loop_mock)
        proto._negotiate_done = True
        proto.data_received(b'123')

    def test_eof_received(self):
        loop_mock = mock.Mock()
        app_proto = mock.Mock()

        proto = make_base(loop_mock, ap_factory=lambda: app_proto)

        # negotiate not completed
        proto._negotiate_done = False
        proto.eof_received()
        self.assertFalse(proto._app_protocol.eof_received.called)

        # negotiate successfully competed
        app_proto.reset_mock()
        proto._negotiate_done = True
        proto.eof_received()
        self.assertTrue(proto._app_protocol.eof_received.called)

        # don't call pause_writing, if app_protocol == self
        # otherwise recursion
        app_proto.reset_mock()
        proto = make_base(loop_mock)
        proto._negotiate_done = True
        proto.eof_received()

    def test_make_ssl_proto(self):
        loop_mock = mock.Mock()
        app_proto = mock.Mock()

        ssl_context = ssllib.create_default_context()
        proto = make_base(loop_mock,
                          ap_factory=lambda: app_proto, ssl=ssl_context)
        proto.socks_request = fake_coroutine((None, None))
        proto._transport = mock.Mock()
        self.loop.run_until_complete(proto.negotiate(None, None))

        self.assertTrue(loop_mock._make_ssl_transport.called)
        self.assertIs(loop_mock._make_ssl_transport.call_args[1]['sslcontext'],
                      ssl_context)

    @mock.patch('aiosocks.protocols.asyncio.Task')
    def test_func_negotiate_cb_call(self, task_mock):
        loop_mock = mock.Mock()
        waiter = mock.Mock()

        proto = make_base(loop_mock, waiter=waiter)
        proto.socks_request = fake_coroutine((None, None))
        proto._negotiate_done_cb = mock.Mock()

        self.loop.run_until_complete(proto.negotiate(None, None))
        self.assertTrue(proto._negotiate_done_cb.called)
        self.assertFalse(task_mock.called)

    @mock.patch('aiosocks.protocols.asyncio.Task')
    def test_coro_negotiate_cb_call(self, task_mock):
        loop_mock = mock.Mock()
        waiter = mock.Mock()

        proto = make_base(loop_mock, waiter=waiter)
        proto.socks_request = fake_coroutine((None, None))
        proto._negotiate_done_cb = fake_coroutine(None)

        self.loop.run_until_complete(proto.negotiate(None, None))
        self.assertTrue(proto._negotiate_done_cb.called)
        self.assertTrue(task_mock.called)

    def test_reader_limit(self):
        proto = BaseSocksProtocol(None, None, ('python.org', 80),
                                  None, None, reader_limit=10,
                                  loop=self.loop)
        self.assertEqual(proto.reader._limit, 10)

        proto = BaseSocksProtocol(None, None, ('python.org', 80),
                                  None, None, reader_limit=15,
                                  loop=self.loop)
        self.assertEqual(proto.reader._limit, 15)


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

    def test_dst_domain_with_remote_resolve(self):
        proto = make_socks4(self.loop, dst=('python.org', 80),
                            r=b'\x00\x5a\x00P\x7f\x00\x00\x01')

        req = proto.socks_request(c.SOCKS_CMD_CONNECT)
        self.loop.run_until_complete(req)

        proto._stream_writer.write.assert_called_with(
            b'\x04\x01\x00P\x00\x00\x00\x01user\x00python.org\x00'
        )

    def test_dst_domain_with_local_resolve(self):
        proto = make_socks4(self.loop, dst=('python.org', 80),
                            rr=False, r=b'\x00\x5a\x00P\x7f\x00\x00\x01')

        req = proto.socks_request(c.SOCKS_CMD_CONNECT)
        self.loop.run_until_complete(req)

        proto._stream_writer.write.assert_called_with(
            b'\x04\x01\x00P\x7f\x00\x00\x01user\x00'
        )

    def test_dst_ip_with_remote_resolve(self):
        proto = make_socks4(self.loop, dst=('127.0.0.1', 8800),
                            r=b'\x00\x5a\x00P\x7f\x00\x00\x01')
        req = proto.socks_request(c.SOCKS_CMD_CONNECT)
        self.loop.run_until_complete(req)

        proto._stream_writer.write.assert_called_with(
            b'\x04\x01"`\x7f\x00\x00\x01user\x00'
        )

    def test_dst_ip_with_locale_resolve(self):
        proto = make_socks4(self.loop, dst=('127.0.0.1', 8800),
                            rr=False, r=b'\x00\x5a\x00P\x7f\x00\x00\x01')

        req = proto.socks_request(c.SOCKS_CMD_CONNECT)
        self.loop.run_until_complete(req)

        proto._stream_writer.write.assert_called_with(
            b'\x04\x01"`\x7f\x00\x00\x01user\x00'
        )

    def test_dst_domain_without_user(self):
        proto = make_socks4(self.loop, auth=aiosocks.Socks4Auth(''),
                            dst=('python.org', 80),
                            r=b'\x00\x5a\x00P\x7f\x00\x00\x01')

        req = proto.socks_request(c.SOCKS_CMD_CONNECT)
        self.loop.run_until_complete(req)

        proto._stream_writer.write.assert_called_with(
            b'\x04\x01\x00P\x00\x00\x00\x01\x00python.org\x00'
        )

    def test_dst_ip_without_user(self):
        proto = make_socks4(self.loop, auth=aiosocks.Socks4Auth(''),
                            dst=('127.0.0.1', 8800),
                            r=b'\x00\x5a\x00P\x7f\x00\x00\x01')
        req = proto.socks_request(c.SOCKS_CMD_CONNECT)
        self.loop.run_until_complete(req)

        proto._stream_writer.write.assert_called_with(
            b'\x04\x01"`\x7f\x00\x00\x01\x00'
        )

    def test_valid_resp_handling(self):
        proto = make_socks4(self.loop, r=b'\x00\x5a\x00P\x7f\x00\x00\x01')
        req = ensure_future(
            proto.socks_request(c.SOCKS_CMD_CONNECT), loop=self.loop)
        self.loop.run_until_complete(req)

        self.assertEqual(req.result(), (('python.org', 80), ('127.0.0.1', 80)))

    def test_invalid_reply_resp_handling(self):
        proto = make_socks4(self.loop, r=b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF')
        req = proto.socks_request(c.SOCKS_CMD_CONNECT)

        with self.assertRaises(aiosocks.InvalidServerReply):
            self.loop.run_until_complete(req)

    def test_socks_err_resp_handling(self):
        proto = make_socks4(self.loop, r=b'\x00\x5b\x00P\x7f\x00\x00\x01')
        req = proto.socks_request(c.SOCKS_CMD_CONNECT)

        with self.assertRaises(aiosocks.SocksError) as cm:
            self.loop.run_until_complete(req)

        self.assertTrue('0x5b' in str(cm.exception))

    def test_unknown_err_resp_handling(self):
        proto = make_socks4(self.loop, r=b'\x00\x5e\x00P\x7f\x00\x00\x01')
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

    def test_auth_inv_srv_ver(self):
        proto = make_socks5(self.loop, r=b'\x00\x00')
        req = proto.authenticate()

        with self.assertRaises(aiosocks.InvalidServerVersion):
            self.loop.run_until_complete(req)

    def test_auth_no_acceptable_auth_methods(self):
        proto = make_socks5(self.loop, r=b'\x05\xFF')
        req = proto.authenticate()
        with self.assertRaises(aiosocks.NoAcceptableAuthMethods):
            self.loop.run_until_complete(req)

    def test_auth_unsupported_auth_method(self):
        proto = make_socks5(self.loop, r=b'\x05\xF0')
        req = proto.authenticate()
        with self.assertRaises(aiosocks.InvalidServerReply):
            self.loop.run_until_complete(req)

    def test_auth_usr_pwd_granted(self):
        proto = make_socks5(self.loop, r=(b'\x05\x02', b'\x01\x00',))
        self.loop.run_until_complete(proto.authenticate())
        proto._stream_writer.write.assert_has_calls([
            mock.call(b'\x05\x02\x00\x02'),
            mock.call(b'\x01\x04user\x03pwd')
        ])

    def test_auth_invalid_reply(self):
        proto = make_socks5(self.loop, r=(b'\x05\x02', b'\x00\x00',))
        req = proto.authenticate()
        with self.assertRaises(aiosocks.InvalidServerReply):
            self.loop.run_until_complete(req)

    def test_auth_access_denied(self):
        proto = make_socks5(self.loop, r=(b'\x05\x02', b'\x01\x01',))
        req = proto.authenticate()
        with self.assertRaises(aiosocks.LoginAuthenticationFailed):
            self.loop.run_until_complete(req)

    def test_auth_anonymous_granted(self):
        proto = make_socks5(self.loop, r=b'\x05\x00')
        req = proto.authenticate()
        self.loop.run_until_complete(req)

    def test_build_dst_addr_ipv4(self):
        proto = make_socks5(self.loop)
        c = proto.build_dst_address('127.0.0.1', 80)
        dst_req, resolved = self.loop.run_until_complete(c)

        self.assertEqual(dst_req, [0x01, b'\x7f\x00\x00\x01', b'\x00P'])
        self.assertEqual(resolved, ('127.0.0.1', 80))

    def test_build_dst_addr_ipv6(self):
        proto = make_socks5(self.loop)
        c = proto.build_dst_address(
            '2001:0db8:11a3:09d7:1f34:8a2e:07a0:765d', 80)
        dst_req, resolved = self.loop.run_until_complete(c)

        self.assertEqual(dst_req, [
            0x04, b' \x01\r\xb8\x11\xa3\t\xd7\x1f4\x8a.\x07\xa0v]', b'\x00P'])
        self.assertEqual(resolved,
                         ('2001:0db8:11a3:09d7:1f34:8a2e:07a0:765d', 80))

    def test_build_dst_addr_domain_with_remote_resolve(self):
        proto = make_socks5(self.loop)
        c = proto.build_dst_address('python.org', 80)
        dst_req, resolved = self.loop.run_until_complete(c)

        self.assertEqual(dst_req, [0x03, b'\n', b'python.org', b'\x00P'])
        self.assertEqual(resolved, ('python.org', 80))

    def test_build_dst_addr_domain_with_locale_resolve(self):
        proto = make_socks5(self.loop, rr=False)
        c = proto.build_dst_address('python.org', 80)
        dst_req, resolved = self.loop.run_until_complete(c)

        self.assertEqual(dst_req, [0x01, b'\x7f\x00\x00\x01', b'\x00P'])
        self.assertEqual(resolved, ('127.0.0.1', 80))

    def test_rd_addr_ipv4(self):
        proto = make_socks5(
            self.loop, r=[b'\x01', b'\x7f\x00\x00\x01', b'\x00P'])
        req = ensure_future(proto.read_address(), loop=self.loop)
        self.loop.run_until_complete(req)

        self.assertEqual(req.result(), ('127.0.0.1', 80))

    def test_rd_addr_ipv6(self):
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

    def test_rd_addr_domain(self):
        proto = make_socks5(
            self.loop, r=[b'\x03', b'\n', b'python.org', b'\x00P'])
        req = ensure_future(proto.read_address(), loop=self.loop)
        self.loop.run_until_complete(req)

        self.assertEqual(req.result(), (b'python.org', 80))

    def test_socks_req_inv_ver(self):
        proto = make_socks5(self.loop, r=[b'\x05\x00', b'\x04\x00\x00'])
        req = proto.socks_request(c.SOCKS_CMD_CONNECT)
        with self.assertRaises(aiosocks.InvalidServerVersion):
            self.loop.run_until_complete(req)

    def test_socks_req_socks_srv_err(self):
        proto = make_socks5(self.loop, r=[b'\x05\x00', b'\x05\x02\x00'])
        req = proto.socks_request(c.SOCKS_CMD_CONNECT)
        with self.assertRaises(aiosocks.SocksError) as ct:
            self.loop.run_until_complete(req)

        self.assertTrue(
            'Connection not allowed by ruleset' in str(ct.exception))

    def test_socks_req_unknown_err(self):
        proto = make_socks5(self.loop, r=[b'\x05\x00', b'\x05\xFF\x00'])
        req = proto.socks_request(c.SOCKS_CMD_CONNECT)
        with self.assertRaises(aiosocks.SocksError) as ct:
            self.loop.run_until_complete(req)

        self.assertTrue('Unknown error' in str(ct.exception))

    def test_socks_req_cmd_granted(self):
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
        proto._stream_writer.write.assert_has_calls([
            mock.call(b'\x05\x02\x00\x02'),
            mock.call(b'\x05\x01\x00\x03\npython.org\x00P')
        ])
