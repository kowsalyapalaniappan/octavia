# Copyright 2017 Walmart Labs
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import os
import subprocess

import mock

from oslo_utils import uuidutils

from octavia.amphorae.backends.agent.api_server import exabgp
from octavia.common.jinja.haproxy import jinja_cfg
import octavia.tests.unit.base as base

BASE_EXABGP_PATH = '/var/lib/octavia/exabgp'
EXABGP_ID1 = uuidutils.generate_uuid()
FAKE_L3_SWITCH_IP = '10.0.0.99'
FAKE_IP_IPV4 = '10.0.0.2'
FAKE_MAC_ADDRESS = 'ab:cd:ef:00:ff:77'
FAKE_INTERFACE = 'dummy0'

UBUNTU_EXABGP_CLI = ('python /usr/local/lib/python2.7/dist-packages/exabgp/'
                     'application/cli.py --root ')


class ExaBGPTestCase(base.TestCase):
    @mock.patch('octavia.amphorae.backends.agent.api_server' +
                '.osutils.Ubuntu.get_exabgp_cli')
    def setUp(self, mock_exabgpcli):
        super(ExaBGPTestCase, self).setUp()
        self.jinja_cfg = jinja_cfg.JinjaTemplater(
            base_amp_path=BASE_EXABGP_PATH)
        self.mock_platform = mock.patch("platform.linux_distribution").start()
        self.mock_platform.return_value = ("Ubuntu",)
        mock_exabgpcli.return_value = (
            '/usr/local/lib/python2.7/dist-packages/exabgp/application/cli.py')

        self.test_exabgp = exabgp.ExaBGP()

    @mock.patch('pyroute2.NSPopen')
    @mock.patch.object(exabgp, "webob")
    @mock.patch('pyroute2.NetNS')
    @mock.patch('pyroute2.IPDB')
    @mock.patch('pyroute2.IPRoute')
    @mock.patch('octavia.amphorae.backends.agent.api_server' +
                '.util.get_process_id')
    def test_register_amphora(self, mock_pid, mock_pyroute2_iproute,
                              mock_pyroute2_ipdb, mock_netns, mock_webob,
                              mock_nspopen):
        mock_pid.return_value = '1245'
        m = mock.mock_open()
        with mock.patch('os.open'), mock.patch.object(os, 'fdopen', m):
            self.test_exabgp.register_amphora(
                vips=[FAKE_IP_IPV4],
                nexthop_ip=FAKE_L3_SWITCH_IP
            )
        mock_webob.Response.assert_any_call(json={
            'message': 'OK',
            'details': 'Amphora registeration is completed'
        }, status=202)
        cmd = (UBUNTU_EXABGP_CLI + "/var/lib/octavia/exabgp" +
               " announce route " + FAKE_IP_IPV4 + "/32 next-hop " +
               FAKE_L3_SWITCH_IP + " origin igp")
        mock_nspopen.assert_called_once_with(
            'amphora-haproxy', cmd.split(), stdin=subprocess.PIPE,
            stderr=subprocess.PIPE, stdout=subprocess.PIPE)

    @mock.patch('os.remove')
    @mock.patch('pyroute2.NSPopen')
    @mock.patch.object(exabgp, "webob")
    @mock.patch('pyroute2.NetNS')
    @mock.patch('pyroute2.IPDB')
    @mock.patch('pyroute2.IPRoute')
    @mock.patch('octavia.amphorae.backends.agent.api_server' +
                '.util.get_process_id')
    @mock.patch('os.path')
    def test_unregister_amphora(self, mock_path, mock_pid,
                                mock_pyroute2_iproute, mock_pyroute2_ipdb,
                                mock_netns, mock_webob, mock_nspopen,
                                mock_remove):
        mock_pid.return_value = '1245'
        m = mock.mock_open()
        with mock.patch('os.open'), mock.patch.object(os, 'fdopen', m):
            self.test_exabgp.unregister_amphora(
                vip=FAKE_IP_IPV4,
                vips=[FAKE_IP_IPV4],
                nexthop_ip=FAKE_L3_SWITCH_IP
            )

        cmd = (UBUNTU_EXABGP_CLI + "/var/lib/octavia/exabgp" +
               " withdraw route " + FAKE_IP_IPV4 + "/32 next-hop " +
               FAKE_L3_SWITCH_IP + " origin igp")

        mock_nspopen.assert_called_once_with(
            'amphora-haproxy', cmd.split(), stdin=subprocess.PIPE,
            stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        mock_webob.Response.assert_any_call(json={
            'message': 'OK',
            'details': 'Unregister Amphora is completed'
        }, status=202)
