#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

# this is a windows documentation stub.  actual code lives in the .ps1
# file of the same name

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = r'''
---
module: win_domain_group_batch
version_added: '2.4'
short_description: Manages Windows Active Directory groups and group membership in batch mode
description:
     - Manages Windows Active Directory groups and group membership in batch mode
options:
  domain_username:
    description:
      - The username to use when interacting with AD.
      - If this is not set then the user Ansible used to log in with will be
        used instead when using CredSSP or Kerberos with credential delegation.
    version_added: '2.5'
  domain_password:
    description:
      - The password for I(username).
    version_added: '2.5'
  domain_server:
    description:
      - Specifies the Active Directory Domain Services instance to connect to.
      - Can be in the form of an FQDN or NetBIOS name.
      - If not specified then the value is based on the domain of the computer
      running PowerShell.
    version_added: '2.5'
  default_name_attr:
    description:
      - Specifies default attribute for object name
    default: 'sAMAccontName'
  default_path:
      - Specifies default OU for groups
  groups:
    - Specifies list of groups:
      sAMAccountName:
        description
          - Specifies group's sAMAccountName
        required: true
      name:
        description:
          - Specifies object's name
        default: <sAMAccountName> or user's default_name_attr
      path:
        description:
          - Specifies object's path
        required: true
      state:
        description:
          - When C(present), creates or updates the user account.  When C(absent),
            removes the user account if it exists.
        choices: [ absent, present ]
        default: present
      category:
        description:
          - Group's category
        choises: [ Distribution, Security ]
        default: Security
      scope:
        description:
          - Group's scope
        choises: [ DomainLocal, Global, Universal ]
        required: true
      clear_attributes:
        description:
          - Specifies list of attributes to be cleared
      attributes:
        description:
          - A dict of custom LDAP attributes to set on the group.
      add_members:
        description:
          - A list of members (sAMAccountName) to be added
      remove_members:
        description:
          - A list of members (sAMAccountName) to be removed
      members:
        description:
          - A list of members (sAMAccountName) to be synced
    required: true

notes:
  - Works with Windows 2016 and newer.
  - If running on a server that is not a Domain Controller, credential
    delegation through CredSSP or Kerberos with delegation must be used or the
    I(domain_username), I(domain_password) must be set.
  - Note that some individuals have confirmed successful operation on Windows
    2008R2 servers with AD and AD Web Services enabled, but this has not
    received the same degree of testing as Windows 2012R2.
author:
    - Sergey Korolev (@knopki)
'''

EXAMPLES = r'''
- name: Make Active Directory great again
  win_domain_group_batch:
    default_name_attr: "sAMAccountName"
    default_path: "OU=test,DC=example,DC=org"
    domain_username: EXAMPLE\admin-account
    domain_password: SomePas2w0rd
    domain_server: domain@example.loc
    groups:
      - sAMAccountName: gl-sec-msk-psk-lsk
        name: Not Cool Group
        state: absent
      - sAMAccountName: gl-admins
        name: Administratorz
        path: "OU=Security Groups,DC=example,DC=loc"
        attributes:
          displayName: "Administratorz"
        clear_attributes:
          - blabla
      - sAMAccountName: gl-users
        name: Userz
        members:
          - mr_cool_guy

- name: Changed data in active directory
  debug: msg="{{ result.diff }}"
  when: result.changed == true
'''

RETURN = r'''
changed:
    description: true if the group changed during execution
    returned: always
    type: boolean
    sample: false
diff:
    description: tree of changed data
    returned: always
    type: dict
    sample:
      cool-group:
        path:
          new: "OU=coolOU,DC=example,DC=loc"
          old: "OU=notCoolOU,DC=example,DC=loc"
        name:
          new: "Cool Group"
          old: "kekeke-group"
'''
