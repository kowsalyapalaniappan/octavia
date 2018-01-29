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
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import ipaddress
import logging
import os
import subprocess

import flask
from oslo_config import cfg
import pyroute2
import six
import webob
from werkzeug import exceptions

from octavia.amphorae.backends.agent.api_server import osutils
from octavia.amphorae.backends.agent.api_server import util
from octavia.common import constants as consts

LOG = logging.getLogger(__name__)
BUFFER = 100

CONF = cfg.CONF


class ExaBGP(object):
    def __init__(self):
        self._osutils = osutils.BaseOS.get_os_util()
        self.exabgp_cli = self._osutils.get_exabgp_cli()

    def exabgp_service_manager(self, action):
        # To execute service start or stop or reload operations

        action = action.lower()
        if action not in [consts.AMP_ACTION_START,
                          consts.AMP_ACTION_STOP,
                          consts.AMP_ACTION_RELOAD]:
            return webob.Response(json=dict(
                message='Invalid Request',
                details="Unknown action: {0}".format(action)), status=400)

        cmd = ("/usr/sbin/service exabgp {action}".format(
            action=action))

        try:
            subprocess.check_output(cmd.split(), stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            LOG.debug('Failed to %s exabgp service: %s', action, e)
            return webob.Response(json=dict(
                message="Failed to {0} exabgp service".format(action),
                details=e.output), status=500)

        return webob.Response(
            json=dict(message='OK',
                      details='exabgp {action}ed'.format(action=action)),
            status=202)

    def upload_exabgp_config(self):
        file = flask.request.files['conf_file']

        if not os.path.exists(CONF.amphora_agent.exabgp_base_path):
            os.makedirs(CONF.amphora_agent.exabgp_base_path)

        file_name = os.path.join(CONF.amphora_agent.exabgp_base_path,
                                 'exabgp.conf')

        file.save(file_name)

        # use exabgp validate check on configuration
        cmd = "exabgp -t {config_file}".format(config_file=file_name)

        try:
            subprocess.check_output(cmd.split(), stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            LOG.error("Failed to validate exabgp file: %s", e)
            return webob.Response(
                json=dict(message="Invalid request", details=e.output),
                status=400)

        exabgp_pid = util.get_process_id('exabgp')

        if exabgp_pid:
            LOG.debug('Found exabp pid: %s', exabgp_pid)

            cmd = "kill -SIGUSR1 {pid}".format(pid=exabgp_pid)
            try:
                subprocess.check_output(cmd.split(), stderr=subprocess.STDOUT)
            except subprocess.CalledProcessError as e:
                LOG.error("Failed to reload exabgp file: %s", e)

        res = webob.Response(json={'message': 'OK'}, status=202)
        return res

    def _check_exabgp_exists(self):
        # check if we know about that exabgp
        exabgp_pid = util.get_process_id('exabgp')
        if not exabgp_pid:
            raise exceptions.HTTPException(
               response=webob.Response(json=dict(
                  message='Exabgp Not Found',
                  details="No exabpg found"), status=404))

    def _check_exabgp_status(self):

        exabgp_pid = util.get_process_id('exabgp')

        cmd = ("cat /proc/{pid}/status").format(pid=exabgp_pid)
        LOG.debug("_check_exabgp_status : %s", cmd)

        output = ""
        try:
            output = subprocess.check_output(cmd.split(),
                                             stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            LOG.error("Failed to verify exabgp status: %s", e)

        out = output.split('\n')[1].split()[1]

        return out

    def get_status(self):
        self._check_exabgp_exists()
        stats = []
        status = self._check_exabgp_status()

        if status == "R":
            stats.append(dict(
                status="running", ))
        elif status == "S":
            stats.append(dict(
                status="sleeping", ))
        else:
            raise exceptions.HTTPException(
                response=webob.Response(json=dict(
                    message='Exabgp unknown status',
                    details="Unknown status"), status=404))

        return webob.Response(json=stats)

    def _popluate_vip_with_versions(self, vips):
        vip_list = []
        for vip in vips:
            ip = ipaddress.ip_address(vip if isinstance(vip, six.text_type)
                                      else six.u(vip))
            vip_list.append(dict(
                vip=str(ip),
                version=ip.version
            ))

        return vip_list

    def register_amphora(self, vips, nexthop_ip):
        self._check_exabgp_exists()

        vip_list = self._popluate_vip_with_versions(vips)

        # put the VIPs interface as dummy0
        dummy_interface = consts.NETNS_DUMMY_INTERFACE

        interface_file_path = self._osutils.get_network_interface_file(
            dummy_interface)

        # Assumming the netns dir is exist
        self._osutils.write_dummy_vip_interface_file(
            interface_file_path=interface_file_path,
            dummy_interface=dummy_interface,
            vip_list=vip_list
        )

        with pyroute2.IPRoute() as ipr:
            # Move the interfaces into the namespace
            idx = ipr.link_lookup(ifname=dummy_interface)[0]
            ipr.link('set', index=idx,
                     net_ns_fd=consts.AMPHORA_NAMESPACE,
                     IFLA_IFNAME=dummy_interface)

        # bring interfaces up
        ip = pyroute2.IPDB(nl=pyroute2.NetNS(consts.AMPHORA_NAMESPACE))
        ip.interfaces[dummy_interface].up().commit()
        ip.release()

        LOG.debug("Adding VIP to dummy0 completed.")

        for vip in vips:
            ip = ipaddress.ip_address(vip if isinstance(vip, six.text_type)
                                      else six.u(vip))
            if ip.version == 4:
                vip_with_prefix = vip + '/32'
            elif ip.version == 6:
                vip_with_prefix = vip + '/128'

            cmd = ('python ' + self.exabgp_cli + ' --root ' +
                   CONF.amphora_agent.exabgp_base_path + ' announce route ' +
                   vip_with_prefix + ' next-hop ' + nexthop_ip + ' origin igp')

            LOG.debug("Announce command : " + cmd)
            nsp = pyroute2.NSPopen(consts.AMPHORA_NAMESPACE, cmd.split(),
                                   stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
            nsp.communicate()
            nsp.wait()
            nsp.release()

        return webob.Response(
            json=dict(message='OK',
                      details='Amphora registeration is completed'),
            status=202)

    def unregister_amphora(self, vip, vips, nexthop_ip):
        self._check_exabgp_exists()

        ip = ipaddress.ip_address(vip if isinstance(vip, six.text_type)
                                  else six.u(vip))
        if ip.version == 4:
            vip_with_prefix = vip + '/32'
        elif ip.version == 6:
            vip_with_prefix = vip + '/128'

        cmd = ('python ' + self.exabgp_cli + ' --root ' +
               CONF.amphora_agent.exabgp_base_path + " withdraw route " +
               vip_with_prefix + " next-hop " + nexthop_ip + " origin igp")

        LOG.debug("Withdraw command : " + cmd)

        nsp = pyroute2.NSPopen(consts.AMPHORA_NAMESPACE, cmd.split(),
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
        nsp.communicate()
        nsp.wait()
        nsp.release()

        LOG.debug("Withdraw route completed")

        dummy_interface = consts.NETNS_DUMMY_INTERFACE

        ip = pyroute2.IPDB(nl=pyroute2.NetNS(consts.AMPHORA_NAMESPACE))

        ip.interfaces[dummy_interface].del_ip(vip_with_prefix).commit()
        ip.release()

        # remove entry in dummy interface file
        vip_list = self._popluate_vip_with_versions(vips)

        # put the VIPs interface as dummy0
        dummy_interface = consts.NETNS_DUMMY_INTERFACE

        interface_file_path = self._osutils.get_network_interface_file(
            dummy_interface)

        # updating config file with remaining entries.
        self._osutils.write_dummy_vip_interface_file(
            interface_file_path=interface_file_path,
            dummy_interface=dummy_interface,
            vip_list=vip_list
        )

        LOG.debug("Remove VIP from dummy0 completed.")

        return webob.Response(
            json=dict(message='OK',
                      details='Unregister Amphora is completed'),
            status=202)

    def service_disable(self):
        cmd = "/bin/systemctl stop exabgp"
        try:
            subprocess.check_output(cmd.split(), stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            LOG.debug('Failed to stop exabgp service: %s', e)
            return webob.Response(json=dict(
                message="Failed to stop exabgp service",
                details=e.output), status=500)

        cmd = "/bin/systemctl disable exabgp"
        try:
            subprocess.check_output(cmd.split(), stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            LOG.debug('Failed to disable exabgp service: %s', e)
            return webob.Response(json=dict(
                message="Failed to disbale exabgp service",
                details=e.output), status=500)

        return webob.Response(json=dict(message='OK',
                              details='exabgp service disabled', status=202))
