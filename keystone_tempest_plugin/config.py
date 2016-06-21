# Copyright 2016 Red Hat, Inc.
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


from oslo_config import cfg


identity_group = cfg.OptGroup(name='identity',
                              title="Keystone Configuration Options")

IdentityGroup = []

identity_feature_group = cfg.OptGroup(name='identity-feature-enabled',
                                      title='Enabled Identity Features')

IdentityFeatureGroup = []

fed_scenario_group = cfg.OptGroup(name='fed_scenario',
                                  title='Federation Scenario Tests Options')

FedScenarioGroup = [
    # Identity Provider
    cfg.StrOpt('idp_id',
               help='The Identity Provider ID'),
    cfg.StrOpt('idp_remote_ids',
               default='',
               help='The Identity Provider remote IDs'),
    cfg.StrOpt('idp_username',
               help='Username used to login in the Identity Provider'),
    cfg.StrOpt('idp_password',
               help='Password used to login in the Identity Provider'),
    cfg.StrOpt('idp_ecp_url',
               help='Identity Provider SAML2/ECP URL'),

    # Mapping rules
    cfg.StrOpt('mapping_remote_type',
               help='The assertion attribute to be used in the remote rules'),
    cfg.StrOpt('mapping_user_id',
               help='The user ID to be used in the local rules'),
    cfg.StrOpt('mapping_group_id',
               help='The group ID to be used in the local rules. The group '
                    'must have at least one assignment in one project.'),

    # Protocol
    cfg.StrOpt('protocol_id',
               default='saml2',
               help='The Protocol ID')
]
