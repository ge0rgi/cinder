# Copyright 2015 OpenStack Foundation
#Copyright 2017 Georgi Georgiev
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

#   ge0rgi: Adapted version of nova/configuration/scheduler.py to add trusted_computing options for cinder scheduler

from oslo_config import cfg



trust_group = cfg.OptGroup(name="trusted_computing",
                           title="Trust parameters",
                           help="""
Configuration options for enabling Trusted Platform Module.
""")

trusted_opts = [
    cfg.StrOpt("attestation_server",
            help="""
The host to use as the attestation server.

Cloud computing pools can involve thousands of compute nodes located at
different geographical locations, making it difficult for cloud providers to
identify a node's trustworthiness. When using the Trusted filter, users can
request that their VMs only be placed on nodes that have been verified by the
attestation server specified in this option.

This option is only used by the FilterScheduler and its subclasses; if you use
a different scheduler, this option has no effect. Also note that this setting
only affects scheduling if the 'TrustedFilter' filter is enabled.

Possible values:

* A string representing the host name or IP address of the attestation server,
  or an empty string.

Related options:

* attestation_server_ca_file
* attestation_port
* attestation_api_url
* attestation_auth_blob
* attestation_auth_timeout
* attestation_insecure_ssl
"""),
    cfg.StrOpt("attestation_server_ca_file",
            help="""
The absolute path to the certificate to use for authentication when connecting
to the attestation server. See the `attestation_server` help text for more
information about host verification.

This option is only used by the FilterScheduler and its subclasses; if you use
a different scheduler, this option has no effect. Also note that this setting
only affects scheduling if the 'TrustedFilter' filter is enabled.

Possible values:

* A string representing the path to the authentication certificate for the
  attestation server, or an empty string.

Related options:

* attestation_server
* attestation_port
* attestation_api_url
* attestation_auth_blob
* attestation_auth_timeout
* attestation_insecure_ssl
"""),
    cfg.PortOpt("attestation_port",
            default=8443,
            help="""
The port to use when connecting to the attestation server. See the
`attestation_server` help text for more information about host verification.

This option is only used by the FilterScheduler and its subclasses; if you use
a different scheduler, this option has no effect. Also note that this setting
only affects scheduling if the 'TrustedFilter' filter is enabled.

Related options:

* attestation_server
* attestation_server_ca_file
* attestation_api_url
* attestation_auth_blob
* attestation_auth_timeout
* attestation_insecure_ssl
"""),
    cfg.StrOpt("attestation_api_url",
            default="/OpenAttestationWebServices/V1.0",
            help="""
The URL on the attestation server to use. See the `attestation_server` help
text for more information about host verification.

This value must be just that path portion of the full URL, as it will be joined
to the host specified in the attestation_server option.

This option is only used by the FilterScheduler and its subclasses; if you use
a different scheduler, this option has no effect. Also note that this setting
only affects scheduling if the 'TrustedFilter' filter is enabled.

Possible values:

* A valid URL string of the attestation server, or an empty string.

Related options:

* attestation_server
* attestation_server_ca_file
* attestation_port
* attestation_auth_blob
* attestation_auth_timeout
* attestation_insecure_ssl
"""),
    cfg.StrOpt("attestation_auth_blob",
            secret=True,
            help="""
Attestation servers require a specific blob that is used to authenticate. The
content and format of the blob are determined by the particular attestation
server being used. There is no default value; you must supply the value as
specified by your attestation service. See the `attestation_server` help text
for more information about host verification.

This option is only used by the FilterScheduler and its subclasses; if you use
a different scheduler, this option has no effect. Also note that this setting
only affects scheduling if the 'TrustedFilter' filter is enabled.

Possible values:

* A string containing the specific blob required by the attestation server, or
  an empty string.

Related options:

* attestation_server
* attestation_server_ca_file
* attestation_port
* attestation_api_url
* attestation_auth_timeout
* attestation_insecure_ssl
"""),
    # TODO(stephenfin): Add min parameter
    cfg.IntOpt("attestation_auth_timeout",
            default=60,
            help="""
This value controls how long a successful attestation is cached. Once this
period has elapsed, a new attestation request will be made. See the
`attestation_server` help text for more information about host verification.

This option is only used by the FilterScheduler and its subclasses; if you use
a different scheduler, this option has no effect. Also note that this setting
only affects scheduling if the 'TrustedFilter' filter is enabled.

Possible values:

* A integer value, corresponding to the timeout interval for attestations in
  seconds. Any integer is valid, although setting this to zero or negative
  values can greatly impact performance when using an attestation service.

Related options:

* attestation_server
* attestation_server_ca_file
* attestation_port
* attestation_api_url
* attestation_auth_blob
* attestation_insecure_ssl
"""),
    cfg.BoolOpt("attestation_insecure_ssl",
            default=False,
            help="""
When set to True, the SSL certificate verification is skipped for the
attestation service. See the `attestation_server` help text for more
information about host verification.

This option is only used by the FilterScheduler and its subclasses; if you use
a different scheduler, this option has no effect. Also note that this setting
only affects scheduling if the 'TrustedFilter' filter is enabled.

Related options:

* attestation_server
* attestation_server_ca_file
* attestation_port
* attestation_api_url
* attestation_auth_blob
* attestation_auth_timeout
"""),
    cfg.BoolOpt("create_blank_on_trusted", default=True, help="""
                                Specifies if blank volumes shoud be created on trusted nodes only"""),
    cfg.StrOpt("default_asset_tags", default="None", help= """
    Default asset tags for blank volumes """)
]


def register_opts(conf):
    conf.register_group(trust_group)
    conf.register_opts(trusted_opts, group=trust_group)


def list_opts():
    return {
            trust_group: trusted_opts
            }
