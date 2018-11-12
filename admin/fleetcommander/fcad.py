# -*- coding: utf-8 -*-
# vi:ts=2 sw=2 sts=2

# Copyright (C) 2015 Red Hat, Inc.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the licence, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this program; if not, see <http://www.gnu.org/licenses/>.
#
# Authors: Oliver Gutiérrez <ogutierrez@redhat.com>
#          Alberto Ruiz <aruiz@redhat.com>

# TODO: Save and retrieve global policy (Special GPO)
# TODO: Save and load profile priority from profile settings data
# TODO: Filter non FC GPOs?
# TODO: Profile ACLs

import os
import json
import logging
import uuid

from functools import wraps

import dns.resolver
import ldap, ldap.sasl, ldap.modlist
import smbc


GPO_SMB_PATH = '\\\\%s\\SysVol\\%s\\Policies\\%s'
SMB_DIRECTORY_PATH = 'smb://%s/SysVol/%s/Policies/%s'

# TODO: FC_PROFILE_PREFIX = '__FC_PROFILE__'

FC_GLOBAL_POLICY_PROFILE_NAME = '__FC_GLOBAL_POLICY__DO_NOT_MODIFY'
FC_GLOBAL_POLICY_DEFAULT = 1
FC_GLOBAL_POLICY_PROFILE = {
    'name': FC_GLOBAL_POLICY_PROFILE_NAME,
    'description': 'Fleet Commander global settings profile. DO NOT MODIFY',
    'priority': 50,
    'settings': {
        'org.freedesktop.FleetCommander': {
            'global_policy': FC_GLOBAL_POLICY_DEFAULT,
        },
    },
}

def connection_required(f):
    @wraps(f)
    def wrapped(obj, *args, **kwargs):
        obj.connect()
        return f(obj, *args, **kwargs)
    return wrapped


class ADConnector(object):
    """
    Active Directory connector class for Fleet Commander
    """

    CACHED_DOMAIN_DN = None
    CACHED_SERVER_NAME = None

    def __init__(self, domain):
        logging.debug('Initializing domain %s AD connector' % domain)
        self.domain = domain
        self.GPO_BASE_ATTRIBUTES = {
            'objectClass': ['top', 'container', 'groupPolicyContainer'],
            'flags': '0',
            'versionNumber': '1',
            'objectCategory':
                'CN=Group-Policy-Container,CN=Schema,CN=Configuration,%s' % self._get_domain_dn(),
        }

    def _get_domain_dn(self):
        if self.CACHED_DOMAIN_DN is None:
            self.CACHED_DOMAIN_DN = 'DC=%s' % ',DC='.join(
                self.domain.split('.'))
        return self.CACHED_DOMAIN_DN

    def _get_server_name(self):
        logging.debug('Getting LDAP service machine name')
        # Resolve LDAP service machine
        if self.CACHED_SERVER_NAME is None:
            result = dns.resolver.query(
                '_ldap._tcp.dc._msdcs.%s' % self.domain.lower(),
                'SRV')            
            self.CACHED_SERVER_NAME = str(result[0].target)[:-1]
        logging.debug('LDAP server: %s' % self.CACHED_SERVER_NAME)
        return self.CACHED_SERVER_NAME

    def _generate_gpo_uuid(self):
        return '{%s}' % str(uuid.uuid4()).upper()

    def _load_smb_data(self, gpo_uuid):
        # Connect to SMB using kerberos
        ctx = smbc.Context()
        ctx.optionNoAutoAnonymousLogin = True
        ctx.optionUseKerberos = True
        # Load data
        duri = SMB_DIRECTORY_PATH % (
            self._get_server_name(), self.domain, gpo_uuid)
        furi = '%s/fleet-commander.json' % duri
        file = ctx.open(furi, os.O_RDONLY)
        data = json.loads(file.read())
        file.close()
        return data

    def _save_smb_data(self, gpo_uuid, profile):
        logging.debug('Saving profile settings using samba')
        # Connect to SMB using kerberos
        ctx = smbc.Context()
        ctx.optionNoAutoAnonymousLogin = True
        ctx.optionUseKerberos = True
        # Create directory
        duri = SMB_DIRECTORY_PATH % (
            self._get_server_name(), self.domain, gpo_uuid)
        logging.debug('Creating directory %s' % duri)
        try:
            ctx.mkdir(duri, 0)
        except smbc.ExistsError as e:
            pass
        except Exception as e:
            logging.debug('Error creating directory %s: %s' % (duri, e))
        # Save file
        furi = '%s/fleet-commander.json' % duri
        logging.debug('Saving fleet commander settings in file %s' % furi)
        file = ctx.open(furi, os.O_CREAT | os.O_WRONLY)
        file.write(
            json.dumps({
                'priority': profile['priority'],
                'settings': profile['settings'],
            }))
        file.close()
        logging.debug('Fleet commander settings saved in %s' % furi)

    def _remove_smb_data(self, gpo_uuid):
        # Connect to SMB using kerberos
        ctx = smbc.Context()
        ctx.optionNoAutoAnonymousLogin = True
        ctx.optionUseKerberos = True
        # Write file to server
        duri = 'smb://%s/SysVol/%s/Policies/%s' % (
            self._get_server_name(), self.domain, gpo_uuid)
        furi = '%s/fleet-commander.json' % duri
        # Remove directory (we only care of files created by FC)
        ctx.unlink(furi)
        ctx.rmdir(duri)

    def _check_profile_exists(self, name):
        base_dn = "CN=Policies,CN=System,%s" % self._get_domain_dn()
        filter = '(CN=%s)' % name
        attrs = ['cn']
        resultlist = self.connection.search_s(base_dn, ldap.SCOPE_SUBTREE, filter, attrs)
        return len(resultlist) > 0

    def _get_ldap_profile_data(self, filter):
        base_dn = "CN=Policies,CN=System,%s" % self._get_domain_dn()
        attrs = ['cn', 'displayName', 'description', 'nTSecurityDescriptor']
        resultlist = self.connection.search_s(base_dn, ldap.SCOPE_SUBTREE, filter, attrs)
        if len(resultlist) > 0:
            return resultlist[0][1]
        return None

    def _data_to_profile(self, data):
        cn = data['cn'][0]
        name = data.get('displayName', (cn, ))[0]
        desc = data.get('description', ('', ))[0]
        # TODO: Load security descriptor, parse it and get users and other data.
        #sd = resdata.get('nTSecurityDescriptor', (None, ))[0]
        smb_data = self._load_smb_data(cn)
        profile = {
            'cn': cn,
            'name': name,
            'description': desc,
            'priority': smb_data['priority'],
            'settings': smb_data['settings'],
        }
        return profile

    def connect(self, sanity_check=True):
        """
        Connect to AD server
        """
        # TODO: Check LDAP connection to avoid binding every time
        logging.debug('Connecting to AD LDAP server')
        server_name = self._get_server_name()
        # Connect to LDAP using Kerberos
        logging.debug('Initializing LDAP connection to %s' % server_name)
        self.connection = ldap.initialize('ldap://%s' % server_name)
        self.connection.set_option(ldap.OPT_REFERRALS, 0)
        sasl_auth = ldap.sasl.sasl({}, 'GSSAPI')
        self.connection.protocol_version = 3
        logging.debug('Binding LDAP connection')
        self.connection.sasl_interactive_bind_s("", sasl_auth)
        logging.debug('LDAP connection succesful')

    @connection_required
    def get_global_policy(self):
        ldap_filter = '(displayName=%s)' % FC_GLOBAL_POLICY_PROFILE_NAME
        data = self._get_ldap_profile_data(ldap_filter)
        if data:
            profile = self._data_to_profile(data)
            return profile['settings']['org.freedesktop.FleetCommander']['global_policy']
        else:
            return FC_GLOBAL_POLICY_DEFAULT

    @connection_required
    def set_global_policy(self, policy):
        profile = FC_GLOBAL_POLICY_PROFILE.copy()
        profile['settings']['org.freedesktop.FleetCommander']['global_policy'] = policy
        self.save_profile(profile)

    @connection_required
    def save_profile(self, profile):
        # Check if profile exists
        cn = profile.get('cn', None)
        # Check if profile exists
        old_profile = None
        if cn is not None:
            old_profile = self.get_profile(cn)
            
        if old_profile is not None:
            logging.debug('Profile with cn %s already exists. Modifying' % cn)
            logging.debug('Old profile: %s' % old_profile)
            logging.debug('New profile: %s' % profile)
            # Modify existing profile
            gpo_uuid = profile['cn']

            old_attrs = {
                'displayName': old_profile['name'],
                'description': old_profile['description'],
            }

            new_attrs = {
                'displayName': profile['name'].encode(),
                'description': profile['description'].encode(),
            }

            ldif = ldap.modlist.modifyModlist(old_attrs, new_attrs)
            if not ldif:
                logging.debug('LDIF data is empty. No LDAP modifications needed')
            else:
                logging.debug('LDIF data to be sent to LDAP: %s' % ldif)
                dn = "CN=%s,CN=Policies,CN=System,%s" % (gpo_uuid, self._get_domain_dn())
                logging.debug('Modifying profile under %s' % dn)
                self.connection.modify_s(dn, ldif)
            # TODO: Set priority in settings data
            self._save_smb_data(gpo_uuid, profile)
        else:
            logging.debug('Saving new profile')
            # Create new profile
            gpo_uuid = self._generate_gpo_uuid()
            logging.debug('New profile UUID = %s' % gpo_uuid)
            attrs = self.GPO_BASE_ATTRIBUTES.copy()
            attrs['cn'] = gpo_uuid
            attrs['displayName'] = profile['name'].encode()
            attrs['description'] = profile['description'].encode()
            # TODO: Set priority into settings
            attrs['gPCFileSysPath'] = GPO_SMB_PATH % (
                self._get_server_name(), self.domain, gpo_uuid)
            logging.debug('Profile data to be sent to LDAP: %s' % attrs)
            ldif = ldap.modlist.addModlist(attrs)
            logging.debug('LDIF data to be sent to LDAP: %s' % ldif)
            dn = "CN=%s,CN=Policies,CN=System,%s" % (gpo_uuid, self._get_domain_dn())
            logging.debug('Adding profile under %s' % dn)
            self.connection.add_s(dn, ldif)
            # Save SMB data
            self._save_smb_data(gpo_uuid, profile)
        return gpo_uuid

    @connection_required
    def del_profile(self, name):
        dn = "cn=%s,CN=Policies,CN=System,%s" % (name, self._get_domain_dn())
        try:
            self.connection.delete_s(dn)
        except ldap.LDAPError, e:
            logging.error('Error deleting %s: %s' % (name, e))
        # Remove samba files
        self._remove_smb_data(name)
        # FC: [DEBUG] LDAP connection succesful
        # Nov 06 10:59:36 fcclient.fc.ad org.freedesktop.FleetCommander[19885]: FC: [ERROR] Error deleting {01758A10-0B27-4955-9FF2-3F2E7BF0F957}: {'info': '0000208C: UpdErr: DSID-030A0493, problem 6003 (CANT_ON_NON_LEAF), data 0\n', 'desc': 'Operation not allowed on non-leaf'}
        # Nov 06 10:59:36 fcclient.fc.ad org.freedesktop.FleetCommander[19885]: FC: [DEBUG] Getting LDAP service machine name
        # Nov 06 10:59:36 fcclient.fc.ad org.freedesktop.FleetCommander[19885]: FC: [DEBUG] LDAP server: win-isjcmpkt0ma.fc.ad
        # Nov 06 10:59:36 fcclient.fc.ad org.freedesktop.FleetCommander[19885]: FC: [ERROR] Error removing profile {01758A10-0B27-4955-9FF2-3F2E7BF0F957}: (2, 'No such file or directory')


    @connection_required
    def get_profiles(self):
        profiles = []
        base_dn = "CN=Policies,CN=System,%s" % self._get_domain_dn()
        filter = '(objectclass=groupPolicyContainer)'
        attrs = ['cn', 'displayName', 'description', ]
        resultlist = self.connection.search_s(base_dn, ldap.SCOPE_SUBTREE, filter, attrs)
        for res in resultlist:
            resdata = res[1]
            if resdata:
                cn = resdata['cn'][0]
                name = resdata.get('displayName', (cn,))[0]
                desc = resdata.get('description', ('',))[0]
                profiles.append(
                    (cn, name, desc)
                )
        return profiles

    @connection_required
    def get_profile(self, cn):
        ldap_filter = '(CN=%s)' % cn
        data = self._get_ldap_profile_data(ldap_filter)
        if data:
            return self._data_to_profile(data)


    @connection_required
    def get_profile_rule(self, name):
        pass


if __name__ == '__main__':
    import pprint
    pp = pprint.PrettyPrinter(indent=4)

    test_profile = {
        'cn': 'Profile display name',
        'name': 'Profile display name',
        'description': 'Profile description',
        'settings': {
            'org.gnome.gsettings': {}
        }
    }

    connector = ADConnector('FC.AD')

    # Get profiles
    pp.pprint(connector.get_profiles())
    # Save new profile
    # gpo_uuid = connector.save_profile(test_profile)
    # test_profile['cn'] = gpo_uuid
    # # Get profile
    # pp.pprint(connector.get_profile(gpo_uuid))
    # # Modify profile
    # modified_profile = {
    #     'cn': gpo_uuid,
    #     'name': 'Modified profile display name',
    #     'description': 'Modified profile description',
    #     'settings': {
    #         'org.gnome.gsettings': {},
    #         'org.freedesktop.FleetCommander': {}
    #     }
    # }
    # connector.save_profile(modified_profile)
    # # Get profile
    # pp.pprint(connector.get_profile(gpo_uuid))
    # # Delete profile
    # # connector.del_profile(gpo_uuid)
    # # Get profiles
    # #pp.pprint(connector.get_profiles())

