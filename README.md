# Ansible module win_domain_group_batch

## Synopsis

* Manages Windows Active Directory groups and group membership in batch mode.

## Options
| parameter  | required | default | choises | comments |
|---|---|---|---|---|
| domain_username | no |   |   | The username to use when interacting with AD. If this is not set then the user Ansible used to log in with will be used instead when using CredSSP or Kerberos with credential delegation. |
| domain_password | no |   |   | The password for *username* |
| domain_server | no |   |   | Specifies the Active Directory Domain Services instance to connect to. Can be in the form of an FQDN or NetBIOS name. If not specified then the value is based on the domain of the computer running PowerShell.  |
| default_name_attr | no | *sAMAccontName* | | Specifies default attribute for object name |
| default_path | yes | | | Specifies default OU for groups |
| groups | yes | | | Specifies list of *groups* (see next table) |

### Groups list
| parameter  | required | default | choises | comments |
|---|---|---|---|---|
| sAMAccountName | yes | | | Specifies group's sAMAccountName |
| name | no | *sAMAccountName* or group's default_name_attr | | Specifies object's name |
| path | yes | | | Specifies object's path |
| state | no | present | absent, present | When *present*, creates or updates the user account.  When *absent*, removes the user account if it exists. |
| category | no | Security | Distribution, Security | Group's category |
| scope | yes | DomainLocal, Global, Universal | Group's scope |
| clear_attributes | no | | | Specifies list of attributes to be cleared |
| attributes | no | | | A dict of custom LDAP attributes to set on the user. |
| add_members | no | | | A list of members (sAMAccountName) to be added |
| remove_members | no | | | A list of members (sAMAccountName) to be removed |
| members | no | | | A list of members (sAMAccountName) to be synced |

## Examples

```yaml
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
```

## Return Values
Common return values are documented here [Return Values](http://docs.ansible.com/ansible/latest/common_return_values.html), the following are the fields unique to this module:

| name | description | returned | type | sample |
|--|--|--|--|--|
| changed | *true* if the group changed during execution | always | boolean | *false* |
| diff | tree of changed data | always | dict of dicts | `cool-group:`<br>&nbsp;`path:`<br>&nbsp;&nbsp;`new: "OU=coolOU,DC=example,DC=loc"`<br>&nbsp;&nbsp;`old: "OU=notCoolOU,DC=example,DC=loc"`<br>&nbsp;`name:`<br>&nbsp;&nbsp;`new: "Cool Group"`<br>&nbsp;&nbsp;`old: "uk-bz-0123"` |

## Notes
* Works with Windows 2016 and newer.
* If running on a server that is not a Domain Controller, credential
    delegation through CredSSP or Kerberos with delegation must be used or the
    I(domain_username), I(domain_password) must be set.
* Note that some individuals have confirmed successful operation on Windows
    2012R2 servers with AD and AD Web Services enabled, but this has not
    received the same degree of testing as Windows 2016.

## Authors
 * Sergey Korolev ([@knopki](http://github.com/knopki))


