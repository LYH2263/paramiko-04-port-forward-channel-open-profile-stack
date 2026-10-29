# Copyright (C) 2024  Paramiko contributors
#
# This file is part of Paramiko.
#
# Paramiko is free software; you can redistribute it and/or modify it under
# the terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# Paramiko is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Paramiko; if not, write to the Free Software Foundation, Inc.,
# 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.

"""
Tests for the Transport-scoped port-forward / channel-open profile stack.

The tests are split per protocol exit, because each exit consumes its own
section of the effective profile:

* reverse-forward control plane  (request_port_forward / cancel / keepalive)
* inbound delivery               (accept queue vs custom tcp callback)
* the three inbound handler slots (tcp / x11 / agent provenance)
* outbound CHANNEL_OPEN tails    (per kind)
* server-mode admission          (dedicated direct check vs generic check)
"""

import socket
import threading
import time
import unittest

from paramiko import Transport, RSAKey, ServerInterface, ChannelOpenProfile
from paramiko import SSHException, ChannelException
from paramiko import OPEN_SUCCEEDED, OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
from paramiko.common import (
    cMSG_GLOBAL_REQUEST, cMSG_CHANNEL_REQUEST, cMSG_CHANNEL_OPEN,
)
from paramiko.message import Message
from tests.loop import LoopSocket
from tests.util import test_path


class RecordingServer(ServerInterface):
    """NullServer-style server with per-leaf call records."""

    def __init__(self, generic_result=OPEN_SUCCEEDED,
                 direct_result=OPEN_SUCCEEDED):
        self.generic_result = generic_result
        self.direct_result = direct_result
        self.generic_calls = []
        self.direct_calls = []
        self.global_requests = []
        self.x11_requests = []
        self.last_channel_open_route = None
        self._listen = None
        from tests.test_transport import NullServer
        # borrow the password auth + x11 accept behaviour of NullServer
        self._null = NullServer()

    def get_allowed_auths(self, username):
        return self._null.get_allowed_auths(username)

    def check_auth_password(self, username, password):
        return self._null.check_auth_password(username, password)

    def check_global_request(self, kind, msg):
        self.global_requests.append(kind)
        return False

    # --- server_admit bearing surface leaf methods ----------------------
    def check_channel_request(self, kind, chanid):
        self.generic_calls.append((kind, chanid))
        return self.generic_result

    def check_channel_direct_tcpip_request(self, chanid, origin, destination):
        self.direct_calls.append((chanid, origin, destination))
        return self.direct_result

    # --- supporting forwards --------------------------------------------
    def check_channel_x11_request(self, channel, single_connection,
                                  auth_protocol, auth_cookie, screen_number):
        self.x11_requests.append(
            (single_connection, auth_protocol, auth_cookie, screen_number))
        return True

    def check_channel_forward_agent_request(self, channel):
        return True

    def check_port_forward_request(self, addr, port):
        self._listen = socket.socket()
        self._listen.bind(('127.0.0.1', 0))
        self._listen.listen(1)
        return self._listen.getsockname()[1]

    def cancel_port_forward_request(self, addr, port):
        if self._listen is not None:
            self._listen.close()
            self._listen = None


class ChannelOpenProfileTest(unittest.TestCase):
    def setUp(self):
        self.socks = LoopSocket()
        self.sockc = LoopSocket()
        self.sockc.link(self.socks)
        self.tc = Transport(self.sockc)
        self.ts = Transport(self.socks)

    def tearDown(self):
        self.tc.close()
        self.ts.close()
        self.socks.close()
        self.sockc.close()

    # ------------------------------------------------------------------
    # harness
    # ------------------------------------------------------------------
    def connect(self, server=None):
        host_key = RSAKey.from_private_key_file(test_path('test_rsa.key'))
        public_host_key = RSAKey(data=host_key.asbytes())
        self.ts.add_server_key(host_key)
        if server is None:
            server = RecordingServer()
        self.server = server
        event = threading.Event()
        self.ts.start_server(event, server)
        self.tc.connect(hostkey=public_host_key,
                        username='slowdive', password='pygmalion')
        event.wait(1.0)
        self.assertTrue(event.is_set())

    def enable_reverse_forward(self, handler=None):
        port = self.tc.request_port_forward('127.0.0.1', 0, handler)
        self.assertEqual(port, self.server._listen.getsockname()[1])
        self.port = port
        return port

    def feed_forwarded(self, settle=0.15):
        """Push one real connection through the server's listener and have
        the server open a forwarded-tcpip channel back to the client."""
        cs = socket.socket()
        cs.connect(('127.0.0.1', self.port))
        ss, _ = self.server._listen.accept()
        rejected = False
        sch = None
        try:
            sch = self.ts.open_forwarded_tcpip_channel(
                ss.getsockname(), ss.getpeername())
        except ChannelException:
            rejected = True
        time.sleep(settle)
        return cs, ss, sch, rejected

    def cleanup_feed(self, cs, ss, sch, cch=None):
        for obj in (sch, cch, ss, cs):
            if obj is not None:
                try:
                    obj.close()
                except Exception:
                    pass

    def spy_global_requests(self):
        calls = []
        orig = self.tc.global_request
        lock = threading.Lock()

        def spy(kind, data=None, wait=True):
            with lock:
                # snapshot the tcp slot so the clear-before-cancel ordering
                # is observable at wire time
                calls.append((kind, wait, self.tc._tcp_handler is not None))
            return orig(kind, data, wait)

        self.tc.global_request = spy
        return calls

    def spy_user_messages(self):
        messages = []
        orig = self.tc._send_user_message

        def spy(m):
            messages.append(Message(m.asbytes()))
            return orig(m)

        self.tc._send_user_message = spy
        return messages

    @staticmethod
    def wait_until(predicate, timeout=2.0):
        deadline = time.time() + timeout
        while not predicate():
            if time.time() > deadline:
                raise AssertionError('condition not met within %ss' % timeout)
            time.sleep(0.02)

    @staticmethod
    def decode_request(msg):
        """Return (type_byte, request_kind, want_reply) for a captured msg."""
        mtype = msg.get_byte()
        if mtype == cMSG_GLOBAL_REQUEST:
            return mtype, msg.get_text(), msg.get_boolean()
        if mtype == cMSG_CHANNEL_REQUEST:
            msg.get_int()
            return mtype, msg.get_text(), msg.get_boolean()
        return mtype, None, None

    # ==================================================================
    # stack mechanics
    # ==================================================================
    def test_stack_empty_view_is_baseline(self):
        stack = self.tc._open_profile_stack
        self.assertEqual(0, len(stack))
        control = stack.effective_forward_control()
        self.assertTrue(control.request_wait)
        self.assertTrue(control.allocate_ephemeral)
        self.assertTrue(control.cancel_clears_handler)
        self.assertFalse(control.forbid_forward)
        delivery = stack.effective_inbound_delivery()
        self.assertFalse(delivery.accept_queue)
        self.assertFalse(delivery.custom_tcp_handler)
        self.assertFalse(delivery.reject_tcp_inbound)
        slots = stack.effective_handler_slots()
        self.assertFalse(slots.tcp_isolated)
        self.assertFalse(slots.x11_via_channel_req)
        self.assertFalse(slots.agent_via_channel_req)
        kinds = stack.effective_channel_open_kind()
        self.assertTrue(kinds.session_plain)
        self.assertTrue(kinds.direct_tcpip_addrs)
        self.assertTrue(kinds.forwarded_tcpip_addrs)
        self.assertTrue(kinds.x11_src_only)
        admit = stack.effective_server_admit()
        self.assertTrue(admit.direct_check)
        self.assertTrue(admit.generic_check)
        self.assertTrue(admit.queue_non_forward)

    def test_stack_push_pop_merges_and_restores(self):
        stack = self.tc._open_profile_stack
        outer = self.tc.push_channel_open_profile(custom_tcp_handler=True)
        try:
            self.assertTrue(
                stack.effective_inbound_delivery().custom_tcp_handler)
            self.assertFalse(stack.effective_inbound_delivery().accept_queue)
            inner = self.tc.push_channel_open_profile(accept_queue=True)
            try:
                # inner pin overlays the outer user profile
                d = stack.effective_inbound_delivery()
                self.assertTrue(d.accept_queue)
                self.assertTrue(d.custom_tcp_handler)
            finally:
                self.tc.pop_channel_open_profile(inner)
            # inner pop restores the outer user profile
            d = stack.effective_inbound_delivery()
            self.assertFalse(d.accept_queue)
            self.assertTrue(d.custom_tcp_handler)
        finally:
            self.tc.pop_channel_open_profile(outer)
        self.assertEqual(0, len(stack))
        self.assertFalse(
            stack.effective_inbound_delivery().custom_tcp_handler)
        # popping below the baseline is an error, never a process-global reset
        self.assertRaises(IndexError, self.tc.pop_channel_open_profile)

    def test_stack_exception_path_unwinds_completely(self):
        stack = self.tc._open_profile_stack
        self.assertRaises(
            RuntimeError,
            self._raise_inside_profile, forbid_forward=True)
        self.assertEqual(0, len(stack))
        # the frame can be pushed again after unwinding, and a pushed frame
        # can itself be used as a context manager (pops on block exit)
        frame = ChannelOpenProfile(accept_queue=True)
        self.tc.push_channel_open_profile(frame)
        self.assertEqual(1, len(stack))
        with frame:
            self.assertTrue(
                stack.effective_inbound_delivery().accept_queue)
        self.assertEqual(0, len(stack))

    def _raise_inside_profile(self, **pins):
        with self.tc.channel_open_profile(**pins):
            self.assertEqual(1, len(self.tc._open_profile_stack))
            raise RuntimeError('boom')

    def test_stack_frame_is_bound_to_one_transport(self):
        frame = self.tc.push_channel_open_profile(forbid_forward=True)
        other = self.ts.push_channel_open_profile(accept_queue=True)
        try:
            # the other Transport's stack must not pop a frame it does not
            # own, even while non-empty
            self.assertRaises(
                SSHException, self.ts._open_profile_stack.pop, frame)
            # a pushed frame cannot be pushed a second time
            self.assertRaises(
                SSHException, self.ts.push_channel_open_profile, frame)
            self.assertEqual(1, len(self.ts._open_profile_stack))
            self.assertEqual(1, len(self.tc._open_profile_stack))
            self.assertIs(other, self.ts._open_profile_stack._frames[-1])
        finally:
            self.ts.pop_channel_open_profile(other)
            self.tc.pop_channel_open_profile(frame)

    def test_two_transports_never_share_a_stack(self):
        self.connect()
        self.tc.push_channel_open_profile(forbid_forward=True)
        self.ts.push_channel_open_profile(accept_queue=True)
        self.assertEqual(1, len(self.tc._open_profile_stack))
        self.assertEqual(1, len(self.ts._open_profile_stack))
        self.assertTrue(
            self.tc._open_profile_stack.effective_forward_control().forbid_forward)
        self.assertFalse(
            self.ts._open_profile_stack.effective_forward_control().forbid_forward)
        self.assertTrue(
            self.ts._open_profile_stack.effective_inbound_delivery().accept_queue)
        self.assertFalse(
            self.tc._open_profile_stack.effective_inbound_delivery().accept_queue)
        # teardown of one session only resets its own stack
        self.tc.close()
        self.assertEqual(0, len(self.tc._open_profile_stack))
        self.assertEqual(1, len(self.ts._open_profile_stack))
        self.ts.pop_channel_open_profile()

    # ==================================================================
    # exit 1: reverse-forward control plane
    # ==================================================================
    def test_tcpip_forward_waits_but_keepalive_does_not(self):
        self.connect()
        calls = self.spy_global_requests()
        self.enable_reverse_forward()
        self.tc.cancel_port_forward('127.0.0.1', self.port)
        # keepalive is the deliberately-fire-and-forget global request
        self.tc.set_keepalive(1)
        time.sleep(2)
        kinds = dict((c[0], c[1]) for c in calls)
        self.assertIn('tcpip-forward', kinds)
        self.assertIn('cancel-tcpip-forward', kinds)
        self.assertIn('keepalive@lag.net', kinds)
        self.assertTrue(kinds['tcpip-forward'],
                        'tcpip-forward must consume its reply (wait=True)')
        self.assertTrue(kinds['cancel-tcpip-forward'])
        self.assertFalse(
            kinds['keepalive@lag.net'],
            'keepalive must stay wait=False and never take a completion slot')
        self.assertIn('keepalive@lag.net', self.server.global_requests)

    def test_forbid_forward_blocks_request_port_forward(self):
        self.connect()
        calls = self.spy_global_requests()
        with self.tc.channel_open_profile(forbid_forward=True):
            self.assertRaises(
                SSHException,
                self.tc.request_port_forward, '127.0.0.1', 0)
            self.assertIsNone(self.tc._tcp_handler)
        # no tcpip-forward wire request while forbidden
        self.assertFalse(
            any(c[0] == 'tcpip-forward' for c in calls))
        # after the frame pops, the control plane works again
        self.enable_reverse_forward()

    def test_ephemeral_port_consumed_from_success_reply(self):
        self.connect()
        with self.tc.channel_open_profile(allocate_ephemeral=True):
            port = self.tc.request_port_forward('127.0.0.1', 0)
        self.assertEqual(port, self.server._listen.getsockname()[1])
        self.assertNotEqual(0, port)

    def test_cancel_clears_tcp_slot_before_wire_cancel(self):
        self.connect()
        self.enable_reverse_forward(handler=lambda *a: None)
        self.assertIsNotNone(self.tc._tcp_handler)
        self.assertEqual(
            ('global:tcpip-forward', 'custom'),
            self.tc._inbound_handler_provenance['tcp'])
        calls = self.spy_global_requests()
        with self.tc.channel_open_profile(cancel_clears_handler=True):
            self.tc.cancel_port_forward('127.0.0.1', self.port)
        cancel = [c for c in calls if c[0] == 'cancel-tcpip-forward']
        self.assertEqual(1, len(cancel))
        self.assertTrue(cancel[0][1])  # cancel itself still waits
        # the slot was already clear when the wire request went out
        self.assertFalse(cancel[0][2])
        self.assertIsNone(self.tc._tcp_handler)
        self.assertIsNone(self.tc._inbound_handler_provenance['tcp'])
        # and a late inbound forwarded-tcpip is now refused (client mode);
        # the server already closed its listener, so open the wire channel
        # directly rather than driving a real socket
        self.assertRaises(
            ChannelException,
            self.ts.open_forwarded_tcpip_channel,
            ('127.0.0.1', self.port), ('9.9.9.9', 1))

    # ==================================================================
    # exit 2: inbound delivery of forwarded-tcpip
    # ==================================================================
    def test_nested_accept_queue_overrides_outer_custom_handler(self):
        self.connect()
        delivered = []

        def custom(channel, origin, server):
            delivered.append(channel)

        self.enable_reverse_forward(handler=custom)
        outer = self.tc.push_channel_open_profile(custom_tcp_handler=True)
        try:
            cs, ss, sch, rejected = self.feed_forwarded()
            self.assertFalse(rejected)
            self.assertEqual(1, len(delivered))
            # the callback path never leaks into the accept queue
            self.assertIsNone(self.tc.accept(0.3))
            self.cleanup_feed(cs, ss, sch)

            inner = self.tc.push_channel_open_profile(accept_queue=True)
            try:
                cs, ss, sch, rejected = self.feed_forwarded()
                self.assertFalse(rejected)
                # inner pin forces queue delivery; custom handler untouched
                self.assertEqual(1, len(delivered))
                cch = self.tc.accept(1.0)
                self.assertIsNotNone(cch)
                self.cleanup_feed(cs, ss, sch, cch)
            finally:
                self.tc.pop_channel_open_profile(inner)

            # pop restores the outer callback-only delivery
            cs, ss, sch, rejected = self.feed_forwarded()
            self.assertFalse(rejected)
            self.assertEqual(2, len(delivered))
            self.assertIsNone(self.tc.accept(0.3))
            self.cleanup_feed(cs, ss, sch)
        finally:
            self.tc.pop_channel_open_profile(outer)

    def test_reject_tcp_inbound_sends_open_failure(self):
        self.connect()
        delivered = []
        self.enable_reverse_forward(
            handler=lambda c, o, s: delivered.append(c))
        with self.tc.channel_open_profile(reject_tcp_inbound=True):
            cs, ss, sch, rejected = self.feed_forwarded()
            self.assertTrue(rejected)
        self.assertEqual([], delivered)
        self.assertIsNone(self.tc.accept(0.3))
        self.cleanup_feed(cs, ss, sch)

    def test_custom_tcp_handler_pin_rejects_queueing_default(self):
        self.connect()
        # no user handler: stock default handler would queue for accept()
        self.enable_reverse_forward(handler=None)
        with self.tc.channel_open_profile(custom_tcp_handler=True):
            cs, ss, sch, rejected = self.feed_forwarded()
            self.assertTrue(rejected)
            self.assertIsNone(self.tc.accept(0.3))
        self.cleanup_feed(cs, ss, sch)
        # frame popped: baseline default delivery queues for accept() again
        cs, ss, sch, rejected = self.feed_forwarded()
        self.assertFalse(rejected)
        cch = self.tc.accept(1.0)
        self.assertIsNotNone(cch)
        self.cleanup_feed(cs, ss, sch, cch)

    # ==================================================================
    # exit 3: the three inbound handler slots
    # ==================================================================
    def test_tcp_slot_armed_via_global_request_x11_agent_via_channel_request(self):
        self.connect()
        messages = self.spy_user_messages()
        chan = self.tc.open_session()

        # tcp: GLOBAL_REQUEST tcpip-forward
        self.tc.request_port_forward('127.0.0.1', 0, lambda *a: None)
        self.assertEqual(
            ('global:tcpip-forward', 'custom'),
            self.tc._inbound_handler_provenance['tcp'])

        # x11: CHANNEL_REQUEST x11-req
        chan.request_x11(0, handler=lambda c, a: None)
        self.assertEqual(
            ('channel:x11-req', 'custom'),
            self.tc._inbound_handler_provenance['x11'])

        # agent: CHANNEL_REQUEST auth-agent-req@openssh.com
        chan.request_forward_agent(lambda c: None)
        self.assertEqual(
            ('channel:auth-agent-req', 'custom'),
            self.tc._inbound_handler_provenance['agent'])

        requests = [self.decode_request(Message(x.asbytes()))
                    for x in messages]
        tcp = [r for r in requests
               if r[1] == 'tcpip-forward']
        x11 = [r for r in requests if r[1] == 'x11-req']
        agent = [r for r in requests
                 if r[1] == 'auth-agent-req@openssh.com']
        self.assertEqual(1, len(tcp))
        self.assertEqual(cMSG_GLOBAL_REQUEST, tcp[0][0])
        self.assertTrue(tcp[0][2])
        self.assertEqual(1, len(x11))
        self.assertEqual(cMSG_CHANNEL_REQUEST, x11[0][0])
        self.assertTrue(x11[0][2])
        self.assertEqual(1, len(agent))
        self.assertEqual(cMSG_CHANNEL_REQUEST, agent[0][0])
        # agent forwarding does not consume a channel reply
        self.assertFalse(agent[0][2])
        chan.close()

    def test_x11_agent_slots_can_only_be_armed_via_channel_request(self):
        self.connect()
        with self.tc.channel_open_profile(
                x11_via_channel_req=True, agent_via_channel_req=True):
            self.assertRaises(
                SSHException, self.tc._set_x11_handler, lambda c, a: None)
            self.assertRaises(
                SSHException,
                self.tc._set_forward_agent_handler, lambda c: None)
            # the Channel paths are still allowed, and delivery works
            chan = self.tc.open_session()
            x11_seen = []
            agent_seen = []

            def x11_handler(c, addr):
                # keep a strong reference: the transport map is weak
                x11_seen.append((c, addr))

            chan.request_x11(0, handler=x11_handler)
            chan.request_forward_agent(lambda c: agent_seen.append(c))

            x11_server = self.ts.open_x11_channel(('localhost', 6093))
            self.wait_until(lambda: len(x11_seen) == 1)
            x11_client, x11_addr = x11_seen.pop()
            self.assertEqual(('localhost', 6093), x11_addr)
            agent_server = self.ts.open_forward_agent_channel()
            self.wait_until(lambda: len(agent_seen) == 1)
            agent_client = agent_seen.pop()

            x11_server.close()
            x11_client.close()
            agent_server.close()
            agent_client.close()
            chan.close()

    def test_slots_cannot_be_cross_armed(self):
        self.connect()
        arm = self.tc._arm_inbound_slot
        # arming a slot through another slot's registration path is always
        # refused, regardless of any profile
        self.assertRaises(
            SSHException,
            arm, 'x11', lambda c, a: None, 'global:tcpip-forward', 'custom')
        self.assertRaises(
            SSHException,
            arm, 'tcp', lambda *a: None, 'channel:x11-req', 'custom')
        self.assertRaises(
            SSHException,
            arm, 'agent', lambda c: None, 'global:tcpip-forward', 'custom')
        self.assertRaises(
            SSHException,
            arm, 'tcp', lambda *a: None,
            'channel:auth-agent-req', 'custom')
        # proper arms still work
        self.tc._arm_inbound_slot(
            'tcp', lambda *a: None, 'global:tcpip-forward', 'custom')
        self.tc._arm_inbound_slot(
            'x11', lambda c, a: None, 'channel:x11-req', 'custom')

    def test_tcp_isolated_refuses_markerless_slot_but_delivers_baseline(self):
        self.connect()
        chan = self.tc.open_session()
        seen = []

        def x11_handler(c, addr):
            # hold a strong reference (the channel map is a weak map)
            seen.append((c, addr))

        # baseline (empty stack): a directly-poked x11 slot still delivers
        self.tc._set_x11_handler(x11_handler)
        self.assertIsNone(self.tc._inbound_handler_provenance['x11'])
        x11_server = self.ts.open_x11_channel(('localhost', 6093))
        self.wait_until(lambda: len(seen) == 1)
        x11_client, addr = seen.pop()
        self.assertEqual(('localhost', 6093), addr)
        x11_server.close()
        x11_client.close()

        # under tcp_isolated the markerless slot is not borrowed: inbound x11
        # is refused in client mode and never reaches the foreign slot
        with self.tc.channel_open_profile(tcp_isolated=True):
            try:
                self.ts.open_x11_channel(('localhost', 6094))
                self.fail('markerless x11 slot should be refused')
            except ChannelException:
                pass
        self.assertEqual([], seen)
        # and the tcp slot must never service x11/agent kinds: an unarmed
        # agent kind is refused without touching the registered tcp callback
        tcp_hits = []
        self.enable_reverse_forward(handler=lambda *a: tcp_hits.append(a))
        with self.tc.channel_open_profile(tcp_isolated=True):
            try:
                self.ts.open_forward_agent_channel()
                self.fail('unarmed agent kind should be refused')
            except ChannelException:
                pass
        self.assertEqual([], tcp_hits)
        self.assertEqual([], seen)
        chan.close()

    # ==================================================================
    # exit 4: outbound CHANNEL_OPEN address tails per kind
    # ==================================================================
    def _open_message(self, kind, dest=None, src=None):
        return self.tc._build_channel_open_message(
            kind, 7, 131072, 32768, dest, src)

    def _decode_header(self, m):
        m.rewind()
        self.assertEqual(cMSG_CHANNEL_OPEN, m.get_byte())
        kind = m.get_text()
        chanid = m.get_int()
        window = m.get_int()
        packet = m.get_int()
        return kind, chanid, window, packet

    def test_channel_open_tails_fork_by_kind(self):
        dest = ('127.0.0.1', 443)
        src = ('10.0.0.9', 5555)

        m = self._open_message('session')
        self.assertEqual(('session', 7, 131072, 32768),
                         self._decode_header(m))
        self.assertEqual(b'', m.get_remainder(),
                         'session must carry no address tail')

        m = self._open_message('auth-agent@openssh.com')
        self._decode_header(m)
        self.assertEqual(b'', m.get_remainder(),
                         'auth-agent must carry no address tail')

        m = self._open_message('direct-tcpip', dest, src)
        self._decode_header(m)
        self.assertEqual(dest[0], m.get_text())
        self.assertEqual(dest[1], m.get_int())
        self.assertEqual(src[0], m.get_text())
        self.assertEqual(src[1], m.get_int())
        self.assertEqual(b'', m.get_remainder())

        m = self._open_message('forwarded-tcpip', dest, src)
        self._decode_header(m)
        self.assertEqual(dest[0], m.get_text())
        self.assertEqual(dest[1], m.get_int())
        self.assertEqual(src[0], m.get_text())
        self.assertEqual(src[1], m.get_int())
        self.assertEqual(b'', m.get_remainder())

        m = self._open_message('x11', src=src)
        self._decode_header(m)
        self.assertEqual(src[0], m.get_text())
        self.assertEqual(src[1], m.get_int())
        self.assertEqual(b'', m.get_remainder(),
                         'x11 carries the source pair only, no dest pair')

    def test_plain_kind_can_not_impersonate_addressed_kind(self):
        # addresses passed to a plain kind are ignored, never serialized
        m = self._open_message(
            'session', dest=('1.2.3.4', 22), src=('5.6.7.8', 99))
        self._decode_header(m)
        self.assertEqual(b'', m.get_remainder())

        # addressed kinds require their pairs
        self.assertRaises(
            SSHException, self._open_message, 'direct-tcpip')
        self.assertRaises(
            SSHException, self._open_message, 'forwarded-tcpip',
            ('1.2.3.4', 22), None)
        self.assertRaises(
            SSHException, self._open_message, 'x11')

    def test_channel_open_kind_pins_are_actually_consumed(self):
        with self.tc.channel_open_profile(direct_tcpip_addrs=False):
            self.assertRaises(
                SSHException,
                self._open_message, 'direct-tcpip',
                ('1.2.3.4', 22), ('5.6.7.8', 99))
        with self.tc.channel_open_profile(session_plain=False):
            self.assertRaises(SSHException, self._open_message, 'session')
        with self.tc.channel_open_profile(x11_src_only=False):
            self.assertRaises(
                SSHException, self._open_message, 'x11',
                None, ('5.6.7.8', 99))

    # ==================================================================
    # exit 5: server-mode admission
    # ==================================================================
    def test_server_routes_direct_to_dedicated_check_and_others_generic(self):
        self.connect()
        dest = ('127.0.0.1', 443)
        origin = ('10.0.0.9', 5555)
        direct = self.tc.open_channel('direct-tcpip', dest, origin)
        sdirect = self.ts.accept(1.0)
        self.assertIsNotNone(sdirect)
        self.assertEqual(1, len(self.server.direct_calls))
        self.assertEqual(0, len(self.server.generic_calls))
        _, got_origin, got_destination = self.server.direct_calls[0]
        self.assertEqual(origin, got_origin)
        self.assertEqual(dest, got_destination)
        self.assertEqual('direct-tcpip',
                         self.server.last_channel_open_route)

        session = self.tc.open_session()
        ssession = self.ts.accept(1.0)
        self.assertIsNotNone(ssession)
        kinds = [c[0] for c in self.server.generic_calls]
        self.assertIn('session', kinds)
        self.assertNotIn('direct-tcpip', kinds)
        self.assertEqual('session', self.server.last_channel_open_route)

        direct.close()
        sdirect.close()
        session.close()
        ssession.close()

    def test_direct_check_pin_forces_dedicated_leaf_on_server_side(self):
        # the dedicated leaf refuses; a "catch-all generic" would accept
        server = RecordingServer(
            generic_result=OPEN_SUCCEEDED,
            direct_result=OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED)
        self.connect(server=server)
        self.ts.push_channel_open_profile(direct_check=True)
        try:
            try:
                self.tc.open_channel(
                    'direct-tcpip', ('127.0.0.1', 443), ('10.0.0.9', 5555))
                self.fail('direct-tcpip should be refused by the dedicated '
                          'leaf')
            except ChannelException:
                pass
            # observable on the ServerInterface side: the dedicated leaf ran
            self.assertEqual(1, len(server.direct_calls))
            self.assertNotIn(
                'direct-tcpip', [c[0] for c in server.generic_calls])
        finally:
            self.ts.pop_channel_open_profile()

    def test_generic_check_pin_disables_generic_admission(self):
        self.connect()
        before = len(self.server.generic_calls)
        with self.ts.channel_open_profile(generic_check=False):
            try:
                self.tc.open_session()
                self.fail('generic admission should be disabled')
            except ChannelException:
                pass
        after = len(self.server.generic_calls)
        # the generic leaf was not even consulted
        self.assertEqual(before, after)

    def test_queue_non_forward_false_skips_accept_queue(self):
        self.connect()
        with self.ts.channel_open_profile(queue_non_forward=False):
            try:
                chan = self.tc.open_session()
                chan.close()
            except (SSHException, ChannelException):
                # the un-queued, weakly-held server channel may GC and close
                # before the opener returns; the point is that admission
                # never fed the accept queue
                pass
            self.assertEqual(
                [], self.ts.server_accepts,
                'admitted non-forward channel must not be queued')
            self.assertIsNone(self.ts.accept(0.3))
        # frame popped: successful non-forward admission queues again
        chan = self.tc.open_session()
        schan = self.ts.accept(1.0)
        self.assertIsNotNone(schan)
        chan.close()
        schan.close()


if __name__ == '__main__':
    unittest.main()
