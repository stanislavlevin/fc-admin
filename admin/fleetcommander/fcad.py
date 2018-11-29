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

# TODO: Profile ACLs

import os
import json
import logging
import uuid
import getpass

from functools import wraps

import dns.resolver
import ldap, ldap.sasl, ldap.modlist
import smbc
from samba.ndr import ndr_unpack, ndr_pack
from samba.dcerpc import security
from samba.ntacls import dsacl2fsacl

GPO_SMB_PATH = '\\\\%s\\SysVol\\%s\\Policies\\%s'
SMB_DIRECTORY_PATH = 'smb://%s/SysVol/%s/Policies/%s'

GPO_APPLY_GROUP_POLICY_CAR = 'edacfd8f-ffb3-11d1-b41d-00a0c968f939'

FC_PROFILE_PREFIX = '_FC_%s'

FC_GLOBAL_POLICY_PROFILE_NAME = 'GLOBAL_POLICY__DO_NOT_MODIFY'
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

DEFAULT_GPO_SECURITY_DESCRIPTOR = 'O:%sG:%sD:S:'
GPO_DACL_ACE = '(OA;CI;CR;edacfd8f-ffb3-11d1-b41d-00a0c968f939;;%s)'

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

    def _apply_smb_permissions(self):
        pass

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
        # Load settings and priority from samba file
        smb_data = self._load_smb_data(cn)
        profile = {
            'cn': cn,
            'name': name[len(FC_PROFILE_PREFIX) - 2:],
            'description': desc,
            'priority': smb_data['priority'],
            'settings': smb_data['settings'],
        }
        # Load security descriptor, parse it and get applies data
        sdh = SecurityDescriptorHelper(data['nTSecurityDescriptor'][0], self)
        logging.debug('Loaded security descriptor data: %s' % sdh.to_sddl())
        applies = sdh.get_fc_applies()
        profile.update(applies)
        return profile

    def _security_descriptor_from_profile(self, profile):
        # Security descriptor
        current_user = getpass.getuser().split('@')[0]
        current_user_sid = self.get_user(current_user)['sid']
        shd = SecurityDescriptorHelper(
            DEFAULT_GPO_SECURITY_DESCRIPTOR % (current_user_sid, current_user_sid), self)
        for user in profile['users']:
            obj = self.get_user(user)
            if obj is not None:
                ace = GPO_DACL_ACE % obj['sid']
                shd.add_dacl_ace(ace)
            else:
                logging.warning('User %s does not existt. Ignoring.')
        return shd.to_ldap_sd()

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
        ldap_filter = '(displayName=%s)' % (FC_PROFILE_PREFIX % FC_GLOBAL_POLICY_PROFILE_NAME)
        data = self._get_ldap_profile_data(ldap_filter)
        if data:
            profile = self._data_to_profile(data)
            return profile['settings']['org.freedesktop.FleetCommander']['global_policy']
        else:
            return FC_GLOBAL_POLICY_DEFAULT

    @connection_required
    def set_global_policy(self, policy):
        ldap_filter = '(displayName=%s)' % (FC_PROFILE_PREFIX % FC_GLOBAL_POLICY_PROFILE_NAME)
        data = self._get_ldap_profile_data(ldap_filter)
        if data:
            profile = self._data_to_profile(data)
        else:
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
                'description': FC_PROFILE_PREFIX % old_profile['description'],
                'nTSecurityDescriptor': old_profile['nTSecurityDescriptor'],
            }

            new_attrs = {
                'displayName': FC_PROFILE_PREFIX % profile['name'].encode(),
                'description': profile['description'].encode(),
                'nTSecurityDescriptor': self._security_descriptor_from_profile(profile)
            }

            ldif = ldap.modlist.modifyModlist(old_attrs, new_attrs)
            if not ldif:
                logging.debug('LDIF data is empty. No LDAP modifications needed')
            else:
                logging.debug('LDIF data to be sent to LDAP: %s' % ldif)
                dn = "CN=%s,CN=Policies,CN=System,%s" % (gpo_uuid, self._get_domain_dn())
                logging.debug('Modifying profile under %s' % dn)
                self.connection.modify_s(dn, ldif)
            self._save_smb_data(gpo_uuid, profile)
        else:
            logging.debug('Saving new profile')
            # Create new profile
            gpo_uuid = self._generate_gpo_uuid()
            logging.debug('New profile UUID = %s' % gpo_uuid)
            attrs = self.GPO_BASE_ATTRIBUTES.copy()
            attrs['cn'] = gpo_uuid
            attrs['displayName'] = FC_PROFILE_PREFIX % profile['name'].encode()
            attrs['description'] = profile['description'].encode()
            attrs['gPCFileSysPath'] = GPO_SMB_PATH % (
                self._get_server_name(), self.domain, gpo_uuid)
            logging.debug('Preparing security descriptor')
            attrs['nTSecurityDescriptor'] = self._security_descriptor_from_profile(profile)
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
                if name.startswith(FC_PROFILE_PREFIX[:-2]) and name != FC_PROFILE_PREFIX % FC_GLOBAL_POLICY_PROFILE_NAME:
                    desc = resdata.get('description', ('',))[0]
                    profiles.append(
                        (cn, name[len(FC_PROFILE_PREFIX) - 2:], desc)
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

    # ------------------------------------------

    @connection_required
    def get_user(self, username):
        base_dn = "CN=Users,%s" % self._get_domain_dn()
        filter = '(&(objectclass=user)(CN=%s))' % username
        attrs = ['cn', 'objectSid']
        resultlist = self.connection.search_s(base_dn, ldap.SCOPE_SUBTREE, filter, attrs)
        if len(resultlist) > 0:
            data = resultlist[0]
            return {
                'cn': data[0],
                'username': data[1]['cn'][0],
                'sid': self.get_sid(data[1]['objectSid'][0])
            }
        else:
            return None

    @connection_required
    def get_group(self, groupname):
        base_dn = "%s" % self._get_domain_dn()
        filter = '(&(objectclass=group)(CN=%s))' % groupname
        attrs = ['cn', 'objectSid']
        resultlist = self.connection.search_s(base_dn, ldap.SCOPE_SUBTREE, filter, attrs)
        resultlist = [x for x in resultlist if x[0] is not None]
        if len(resultlist) > 0:
            data = resultlist[0]
            return {
                'cn': data[0],
                'groupname': data[1]['cn'][0],
                'sid': self.get_sid(data[1]['objectSid'][0])
            }
        else:
            return None

    @connection_required
    def get_host(self, hostname):
        base_dn = "CN=Computers,%s" % self._get_domain_dn()
        filter = '(&(objectclass=computer)(CN=%s))' % hostname
        attrs = ['cn', 'objectSid']
        resultlist = self.connection.search_s(base_dn, ldap.SCOPE_SUBTREE, filter, attrs)
        if len(resultlist) > 0:
            data = resultlist[0]
            return {
                'cn': data[0],
                'hostname': data[1]['cn'][0],
                'sid': self.get_sid(data[1]['objectSid'][0])
            }
        else:
            return None

    def get_object_by_sid(self, sid):
        base_dn = "%s" % self._get_domain_dn()
        filter = '(&(|(objectclass=computer)(objectclass=user)(objectclass=group))(objectSid=%s))' % sid
        attrs = ['cn', 'objectClass']
        resultlist = self.connection.search_s(base_dn, ldap.SCOPE_SUBTREE, filter, attrs)
        resultlist = [x for x in resultlist if x[0] is not None]
        if len(resultlist) > 0:
            data = resultlist[0][1]
            return {
                'cn': data['cn'][0],
                'objectClass': data['objectClass']
            }
        else:
            return None

    def get_sid(self, sid_ndr):
        return ndr_unpack(security.dom_sid, sid_ndr)

    def get_domain_sid(self):
        base_dn = "%s" % self._get_domain_dn()
        filter = '(objectClass=*)'
        attrs = ['objectSid']
        resultlist = self.connection.search_s(base_dn, ldap.SCOPE_BASE, filter, attrs)
        return self.get_sid(resultlist[0][1]["objectSid"][0])


class SecurityDescriptorHelper(object):

    def __init__(self, sd, connector):
        self.connector = connector
        self.dacls = []
        self.sacls = []
        if isinstance(sd, security.descriptor):
            # Get the SDDL and parse
            sddl = sd.as_sddl()
        else:
            try:
                # Try to unpack data, then get SDDL and parse
                sd = ndr_unpack(security.descriptor, sd)
                sddl = sd.as_sddl()
            except Exception:
                sddl = sd
        self.parse_sddl(sddl)
    
    def parse_sddl(self, sddl):
        logging.debug('Parsing SDDL for security descriptor. Given SDDL: %s' % sddl)
        # SACLs
        if 'S:' in sddl:    
            sacl_index = sddl.index('S:')
            sacl_data = sddl[sacl_index + 2:]
            if '(' in sacl_data:
                self.sacl_flags = sacl_data[:sacl_data.index('(')]
                sacl_aces = sacl_data[sacl_data.index('('):]
                self.sacls = [ACEHelper(x) for x in sacl_aces[1:][:-1].split(')(')]
            else:
                self.sacl_flags = sacl_data
        else:
            sacl_index = len(sddl) - 1
        # DACLs
        if 'D:' in sddl:
            dacl_index = sddl.index('D:')
            dacl_data = sddl[dacl_index + 2:sacl_index]
            if '(' in dacl_data:
                self.dacl_flags = dacl_data[:dacl_data.index('(')]
                dacl_aces = dacl_data[dacl_data.index('('):]
                self.dacls = [ACEHelper(x) for x in dacl_aces[1:][:-1].split(')(')]
            else:
                self.dacl_flags = dacl_data
        # Group
        g_index = sddl.index('G:')
        self.group_sid = sddl[g_index + 2:dacl_index]
        logging.debug('SDDL parse finished')
        # Owner
        self.owner_sid = sddl[2:g_index]

    def add_dacl_ace(self, ace):
        logging.debug('Adding ACE to security descriptor: %s')
        if ace not in self.dacls:
            self.dacls.append(ACEHelper(str(ace)))
        else:
            logging.debug('ACE %s already exists for this security descriptor')

    def get_fc_applies(self):
        logging.debug('Getting applies from security descriptor ACEs')
        users = set()
        groups = set()
        hosts = set()

        for ace in self.dacls:
            # Manage GPO object ACEs only
            if ace.object_guid == GPO_APPLY_GROUP_POLICY_CAR:
                # Manage ACEs that apply to an user
                obj = self.connector.get_object_by_sid(ace.account_sid)
                if obj is not None:
                    if 'user' in obj['objectClass']:
                        users.add(obj['cn'])
                    elif 'group' in obj['objectClass']:
                        groups.add(obj['cn'])
                    elif 'computer' in obj['objectClass']:
                        hosts.add(obj['cn'])
        applies = {
            'users': list(users),
            'groups': list(groups),
            'hosts': list(hosts),
            'hostgroups': [],
        }
        logging.debug('Retrieved applies: %s' % applies)
        return applies


    def to_sddl(self):
        return 'O:%sG:%sD:%sS:%s' % (
            self.owner_sid,
            self.group_sid,
            '%s%s' % (
                self.dacl_flags,
                ''.join([str(x) for x in self.dacls]),
            ),
            '%s%s' % (
                self.sacl_flags,
                ''.join([str(x) for x in self.sacls]),
            ),
        )

    def to_ldap_sd(self):
        logging.debug('Generating security descriptor')
        sd = security.descriptor()
        sddl = self.to_sddl()
        print(sddl)
        logging.debug('SDDL for security descriptor generation: %s' % sddl)
        domain_sid = self.connector.get_domain_sid()
        sd.from_sddl(sddl, domain_sid)
        for ace in sd.dacl:
            print("ACE %s" % ace)
        print(dir(sd))
        print(sd.as_sddl())
        return ndr_pack(sd)


class ACEHelper(object):

    def __init__(self, ace_string):
        # Remove parenthesis from ACE string
        ace_string = ace_string.replace('(', '').replace(')', '')
        # Split data
        data = ace_string.split(';')
        self.type = data[0]
        self.flags = data[1]
        self.rights = data[2]
        self.object_guid = data[3]
        self.inherit_object_guid = data[4]
        self.account_sid = data[5]
        # Resource attribute is optional
        if len(data) > 6:
            self.resource_attribute = data[6]
        else:
            self.resource_attribute = None

    @property
    def ace_string(self):
        data = [
            self.type,
            self.flags,
            self.rights,
            self.object_guid,
            self.inherit_object_guid,
            self.account_sid,
        ]
        if self.resource_attribute is not None:
            data.append(self.resource_attribute)
        return '(%s)' % ';'.join(data)

    def __eq__(self, other):
        ace_str = str(other)
        return ace_str == self.ace_string

    def __repr__(self):
        return 'ACEHelper%s' % self.ace_string

    def __str__(self):
        return self.ace_string


if __name__ == '__main__':
    import pprint
    pp = pprint.PrettyPrinter(indent=4)

    test_profile = {
        'cn': 'Profile display name4',
        'name': 'Profile display name4',
        'description': 'Profile description',
        'priority': 50,
        'settings': {
            'org.gnome.gsettings': {}
        },
        'users': ['Administrator', 'Pepe',],
        'groups': [],
        'hosts': [],
        'hostgroups': [],
    }

    connector = ADConnector('FC.AD')

    # Get profiles
    # user = connector.get_user('Administrator')
    # pp.pprint(user)

    # host = connector.get_host('FCCLIENT2')
    # pp.pprint(host)

    # group = connector.get_group('GrupoPrueba2')
    # pp.pprint(group)

    # Save new profile
    gpo_uuid = connector.save_profile(test_profile)
    #test_profile['cn'] = gpo_uuid
    #print('UUID: %s' % gpo_uuid)
    # Get profile
    #gpo_uuid = '{3694E9D6-3349-46F0-BC1B-C12D380047D3}'
    profile = connector.get_profile(gpo_uuid)
    print(profile)
    # pp.pprint(connector.get_profile(gpo_uuid))
    # Modify profile
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

    # print('BY SID: %s' % user['sid'], connector.get_object_by_sid(user['sid']))
    # Delete profile
    # connector.del_profile(gpo_uuid)
    # Get profiles
    #pp.pprint(connector.get_profiles())

