# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright (c) 2012 Intel, Inc.
# Copyright (c) 2011-2012 OpenStack Foundation
# Copyright (c) 2017 Georgi Georgiev
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

"""
Filter to add support for Trusted Computing Pools.

Filter that only schedules tasks on a host if the integrity (trust)
of that host matches the trust requested in the `extra_specs' for the
flavor.  The `extra_specs' will contain a key/value pair where the
key is `trust'.  The value of this pair (`trusted'/`untrusted') must
match the integrity of that host (obtained from the Attestation
service) before the task can be scheduled on that host.

Note that the parameters to control access to the Attestation Service
are in the `nova.conf' file in a separate `trust' section.  For example,
the config file will look something like:

    [DEFAULT]
    verbose=True
    ...
    [trust]
    server=attester.mynetwork.com

Details on the specific parameters can be found in the file `trust_attest.py'.

Details on setting up and using an Attestation Service can be found at
the Open Attestation project at:

    https://github.com/OpenAttestation/OpenAttestation
"""
#ge0rgi: Initialized trust_verify
#ge0rgi: Added is_trusted

import urllib2
import httplib
import socket
import backports.ssl as ssl
import json
import ast

from oslo_config import cfg

from oslo_log import log as logging
from cinder.scheduler import filters
from lxml import etree
import base64
import cinder.db.api as db

LOG = logging.getLogger(__name__)

CONF = cfg.CONF


class HTTPSClientAuthConnection(httplib.HTTPSConnection):
    """
    Class to make a HTTPS connection, with support for full client-based
    SSL Authentication
    """

    def __init__(self, host, port, key_file, cert_file, ca_file, timeout=None):
        httplib.HTTPSConnection.__init__(self, host,
                                         key_file=key_file,
                                         cert_file=cert_file)
        self.host = host
        self.port = port
        self.key_file = key_file
        self.cert_file = cert_file
        self.ca_file = ca_file
        self.timeout = timeout

    def connect(self):
        """
        Connect to a host on a given (SSL) port.
        If ca_file is pointing somewhere, use it to check Server Certificate.

        Redefined/copied and extended from httplib.py:1105 (Python 2.6.x).
        This is needed to pass cert_reqs=ssl.CERT_REQUIRED as parameter to
        ssl.wrap_socket(), which forces SSL to check server certificate
        against our client certificate.
        """
        sock = socket.create_connection((self.host, self.port), self.timeout)
        self.sock = ssl.wrap_socket(sock, self.key_file, self.cert_file,
                                    ca_certs=self.ca_file)
        # cert_reqs=ssl.CERT_REQUIRED)


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

    def _do_request(self, method, action_url, params, headers):
        # Connects to the server and issues a request.
        # :returns: result data
        # :raises: IOError if the request fails

        # action_url = "%s" % (self.api_url)
        try:
            c = HTTPSClientAuthConnection(self.host, self.port,
                                          key_file=self.key_file,
                                          cert_file=self.cert_file,
                                          ca_file=self.ca_file)

            c.request(method, action_url, json.dumps(params), headers)
            res = c.getresponse()
            status_code = res.status
            data = res.read()
            c.close()
            if status_code in (httplib.OK,
                               httplib.CREATED,
                               httplib.ACCEPTED,
                               httplib.NO_CONTENT):
                return httplib.OK, data
            return status_code, None

        except (socket.error, IOError):
            return IOError, None

    def _request(self, cmd, subcmd, host_uuid, resp_format="application/samlassertion+xml"):
        # Setup the header & body for the request

        headers = {}
        auth = base64.encodestring(self.auth_blob).replace('\n', '')
        if self.auth_blob:
            headers['x-auth-blob'] = self.auth_blob
            headers['Authorization'] = "Basic " + auth
            headers['Accept'] = resp_format
            # headers['Content-Type'] = 'application/json'
        # status, res = self._do_request(cmd, subcmd, params, headers)
        status, data = self._do_request(cmd, subcmd, host_uuid, headers)
        if status != httplib.OK:
            return status, None
        return status, data


    def do_attestation(self, hostname):
        """Attests compute nodes through OAT service.

        :param hosts: hosts list to be attested
        :returns: dictionary for trust level and validate time
        """
        result = None

        # status, data = self._request("POST", "PollHosts", hosts)
        # status, data = self._request("POST", "", host_uuid)
        action_url = "%s?nameEqualTo=%s" % (self.api_url, hostname)
        status, data = self._request("GET", action_url, hostname)

        return data


class TrustAssertionFilter(filters.BaseBackendFilter):

    def backend_passes(self, backend_state, filter_properties):
        """Only return hosts with required Trust level."""
        verify_asset_tag = False
        verify_trust_status = False

        request_spec = filter_properties['request_spec']
        metadata = filter_properties["metadata"]
        is_blank_volume = request_spec['image_id'] is None and request_spec['snapshot_id'] is None
        if metadata == {} and is_blank_volume and CONF.trusted_computing.create_blank_on_trusted:
            metadata['trust']='trusted'
            metadata['asset_tags']= CONF.trusted_computing.default_asset_tags

        trust_verify = ''
        if ('trust' in metadata):
            trust_verify = 'true'

        LOG.debug(" Verify trust: %s" % trust_verify)

        # if tag_selections is None or tag_selections == 'Trust':
        if trust_verify == 'true':
            # Get the Tag verification flag from the image properties
            if 'asset_tags' in metadata:
                tag_selections = metadata['asset_tags']  # comma seperated values
            else:
                tag_selections = 'None'
            LOG.debug(tag_selections)
            verify_trust_status = True
            if tag_selections != None and tag_selections != {} and tag_selections != 'None':
                verify_asset_tag = True

        if not verify_trust_status:
            # Filter returns success/true if neither trust or tag has to be verified.
            return True

        self.attestservice = AttestationService()
        hostname = backend_state.host.split("@")[0]
        LOG.debug("Getting the attestation report")
        host_data = self.attestservice.do_attestation(hostname)
        trust, asset_tag = self.verify_and_parse_saml(host_data)
        if not trust:
            return False

        if verify_asset_tag:
            # Verify the asset tag restriction
            LOG.debug('Asset tag %s' % asset_tag)
            LOG.debug('Tag selection %s'% tag_selections)
            return self.verify_asset_tag(asset_tag, tag_selections)

        return True

    def verify_and_parse_saml(self, saml_data):
        trust = False
        asset_tag = {}

        # Trust attestation service responds with a JSON in case the given host name is not found
        # Need to update this after the mt. wilson service is updated to return consistent message formats
        try:
            if json.loads(saml_data):
                return trust, asset_tag
        except:
            LOG.debug("System does not exist in the Mt. Wilson portal")

        ns = {'saml2p': '{urn:oasis:names:tc:SAML:2.0:protocol}',
              'saml2': '{urn:oasis:names:tc:SAML:2.0:assertion}'}

        try:
            # xpath strings
            xp_attributestatement = '{saml2}AttributeStatement/{saml2}Attribute'.format(**ns)
            xp_attributevalue = '{saml2}AttributeValue'.format(**ns)

            doc = etree.XML(saml_data)
            elements = doc.findall(xp_attributestatement)

            for el in elements:
                if el.attrib['Name'].lower() == 'trusted':
                    if el.find(xp_attributevalue).text == 'true':
                        trust = True
                elif el.attrib['Name'].lower().startswith("tag"):
                    asset_tag[el.attrib['Name'].lower().split('[')[1].split(']')[0].lower()] = el.find(
                        xp_attributevalue).text.lower()

            return trust, asset_tag
        except:
            return trust, asset_tag

    # Verifies the asset tag match with the tag selections provided by the user.
    def verify_asset_tag(self, host_tags, tag_selections):
        # host_tags is the list of tags set on the host
        # tag_selections is the list of tags set as the policy of the image
        ret_status = False
        selection_details = {}

        try:
            sel_tags = ast.literal_eval(tag_selections.lower())

            iteration_status = True
            for tag in list(sel_tags.keys()):
                if tag not in list(host_tags.keys()) or host_tags[tag] not in sel_tags[tag]:
                    # if tag not in dict((k.lower(),v) for k,v in host_tags.items()).keys() or host_tags[tag.lower()].lower() not in (val.upper() for val in sel_tags[tag]:
                    iteration_status = False
            if (iteration_status):
                ret_status = True
        except:
            ret_status = False

        return ret_status

    def is_trusted(self, hostname, tags= None):
        try:
            # to be called from instance manager on instance strat
            service = AttestationService()
            host_data = service.do_attestation(hostname)
            trust, asset_tag = self.verify_and_parse_saml(host_data)
            if not trust:
                return False
            if tags is not None and tags != 'None' and tags!={}:
                return self.verify_asset_tag(asset_tag, tags)
            return True
        except:
            return False
