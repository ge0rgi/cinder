# Copyright (c) 2012 Intel, Inc.
# Copyright (c) 2011-2012 OpenStack Foundation
#Copyright (c) 2017 Georgi Georgiev
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#    ge0rgi: Adapted Nova Trusted Filter to work for cinder volumes

"""
Filter to add support for Trusted Computing Pools (EXPERIMENTAL).
This is a modified version of the TrustedFilter used by the Nova scheduler.
It schedules storage on trusted hosts.

Configuration options have to be specified in the [trusted_computing] section in cinder.conf

Details on setting up and using an Attestation Service can be found at
the Open Attestation project at:

    https://github.com/OpenAttestation/OpenAttestation
"""

from oslo_log import log as logging
from oslo_serialization import jsonutils
from oslo_utils import timeutils
from oslo_config import cfg
import requests

from cinder.i18n import _LW
from cinder.scheduler import filters


LOG = logging.getLogger(__name__)
CONF = cfg.CONF

class AttestationService(object):
    # Provide access wrapper to attestation server to get integrity report.

    def __init__(self):
        self.api_url = CONF.trusted_computing.attestation_api_url
        self.host = CONF.trusted_computing.attestation_server
        self.port = CONF.trusted_computing.attestation_port
        self.auth_blob = CONF.trusted_computing.attestation_auth_blob
        self.key_file = None
        self.cert_file = None
        self.ca_file = CONF.trusted_computing.attestation_server_ca_file
        self.request_count = 100
        # If the CA file is not provided, let's check the cert if verification
        # asked
        self.verify = (not CONF.trusted_computing.attestation_insecure_ssl
                       and self.ca_file or True)
        self.cert = (self.cert_file, self.key_file)

    def _do_request(self, method, action_url, body, headers):
        # Connects to the server and issues a request.
        # :returns: result data
        # :raises: IOError if the request fails

        action_url = "https://%s:%d%s/%s" % (self.host, self.port,
                                             self.api_url, action_url)
        try:
            res = requests.request(method, action_url, data=body,
                                   headers=headers, cert=self.cert,
                                   verify=self.verify)
            status_code = res.status_code
            if status_code in (requests.codes.OK,
                               requests.codes.CREATED,
                               requests.codes.ACCEPTED,
                               requests.codes.NO_CONTENT):
                try:
                    return requests.codes.OK, jsonutils.loads(res.text)
                except (TypeError, ValueError):
                    return requests.codes.OK, res.text
            return status_code, None

        except requests.exceptions.RequestException:
            return IOError, None

    def _request(self, cmd, subcmd, hosts):
        body = {}
        body['count'] = len(hosts)
        body['hosts'] = hosts
        cooked = jsonutils.dumps(body)
        headers = {}
        headers['content-type'] = 'application/json'
        headers['Accept'] = 'application/json'
        if self.auth_blob:
            headers['x-auth-blob'] = self.auth_blob
        status, res = self._do_request(cmd, subcmd, cooked, headers)
        return status, res

    def do_attestation(self, hosts):
        """Attests compute nodes through OAT service.

        :param hosts: hosts list to be attested
        :returns: dictionary for trust level and validate time
        """
        result = None

        status, data = self._request("POST", "PollHosts", hosts)
        if data is not None:
            result = data.get('hosts')

        return result

class ComputeAttestationCache(object):
    """Cache for compute node attestation

    Cache compute node's trust level for sometime,
    if the cache is out of date, poll OAT service to flush the
    cache.

    OAT service may have cache also. OAT service's cache valid time
    should be set shorter than trusted filter's cache valid time.
    """

    def __init__(self):
        self.attestservice = AttestationService()
        self.storage_nodes = {}

        # TODO(sfinucan): Remove this warning when the named config options
        # gains a 'min' parameter.
        if CONF.trusted_computing.attestation_auth_timeout < 0:
            LOG.warning(_LW('Future versions of nova will restrict the '
                '"trusted_computing.attestation_auth_timeout" config option '
                'to values >=0. Update your configuration file to mitigate '
                'future upgrade issues.'))

    def _cache_valid(self, host):
        cachevalid = False
        if host in self.storage_nodes:
            node_stats = self.storage_nodes.get(host)
            if not timeutils.is_older_than(
                             node_stats['vtime'],
                             CONF.trusted_computing.attestation_auth_timeout):
                cachevalid = True
        return cachevalid

    def _init_cache_entry(self, host):
        self.storage_nodes[host] = {
            'trust_lvl': 'unknown',
            'vtime': timeutils.normalize_time(
                        timeutils.parse_isotime("1970-01-01T00:00:00Z"))}

    def _invalidate_caches(self):
        for host in self.storage_nodes:
            self._init_cache_entry(host)

    def _update_cache_entry(self, state):
        entry = {}

        host = state['host_name']
        entry['trust_lvl'] = state['trust_lvl']

        try:
            # Normalize as naive object to interoperate with utcnow().
            entry['vtime'] = timeutils.normalize_time(
                            timeutils.parse_isotime(state['vtime']))
        except ValueError:
            try:
                # Mt. Wilson does not necessarily return an ISO8601 formatted
                # `vtime`, so we should try to parse it as a string formatted
                # datetime.
                vtime = timeutils.parse_strtime(state['vtime'], fmt="%c")
                entry['vtime'] = timeutils.normalize_time(vtime)
            except ValueError:
                # Mark the system as un-trusted if get invalid vtime.
                entry['trust_lvl'] = 'unknown'
                entry['vtime'] = timeutils.utcnow()

        self.storage_nodes[host] = entry

    def _update_cache(self):
        self._invalidate_caches()
        states = self.attestservice.do_attestation(
            list(self.storage_nodes.keys()))
        if states is None:
            return
        for state in states:
            self._update_cache_entry(state)

    def get_host_attestation(self, host):
        """Check host's trust level."""
        if host not in self.storage_nodes:
            self._init_cache_entry(host)
        if not self._cache_valid(host):
            self._update_cache()
        level = self.storage_nodes.get(host).get('trust_lvl')
        return level


class ComputeAttestation(object):
    def __init__(self):
        self.caches = ComputeAttestationCache()

    def is_trusted(self, host, trust):
        level = self.caches.get_host_attestation(host)
        return trust == level


class TrustedFilter(filters.BaseBackendFilter):
    def __init__(self):
        self.compute_attestation = ComputeAttestation()

    def backend_passes(self, host_state, filter_properties):
        hostname = host_state.host.split('@')[0]
        if 'trust:trusted_host' in filter_properties["metadata"]:
            return self.compute_attestation.is_trusted(hostname, filter_properties['metadata']['trust:trusted_host'])
        return self.compute_attestation.is_trusted(hostname, CONF.trusted_computing.default_trust_level)

