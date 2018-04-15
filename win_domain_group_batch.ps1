#!powershell

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

# WANT_JSON
# POWERSHELL_COMMON

$result = @{
  changed = $false
  diff = @{}
}

function Update-Result ($username, $key, $old, $new) {
  $result.changed = $true
  if (-not $result.diff.containsKey($username)) {
    $result.diff[$username] = @{}
  }
  $result.diff[$username][$key] = @{
    old = $old
    new = $new
  }
}


$ErrorActionPreference = "Stop"

$params = Parse-Args $args -supports_check_mode $true
$check_mode = Get-AnsibleParam -obj $params -name "_ansible_check_mode" -default $false

# Module control parameters
$domain_username = Get-AnsibleParam -obj $params -name "domain_username" -type "str"
$domain_password = Get-AnsibleParam -obj $params -name "domain_password" -type "str" -failifempty ($domain_username -ne $null)
$domain_server = Get-AnsibleParam -obj $params -name "domain_server" -type "str"

# Group account parameters
$default_name_attr = Get-AnsibleParam -obj $params -name "default_name_attr" -type "str" -default "sAMAccountName"
$default_path = Get-AnsibleParam -obj $params -name "default_path" -type "str"

# Create user array
$groups_arr = Get-AnsibleParam -obj $params -name "groups" -type "list" -failifempty $true
$groups = @()
foreach ($g_obj in $groups_arr) {
  $g_h = @{}
  $g_obj.psobject.properties | Foreach { $g_h[$_.Name] = $_.Value }
  $g_h.sAMAccountName = Get-AnsibleParam -obj $g_h -name "sAMAccountName" -type "str" -failifempty $true
  if ($default_path -ne $null) {
    $g_h.path = Get-AnsibleParam -obj $g_h -name "path" -type "str" -default $default_path
  } else {
    $g_h.path = Get-AnsibleParam -obj $g_h -name "path" -type "str" -failifempty $true
  }
  $g_h.state = Get-AnsibleParam -obj $g_h -name "state" -type "str" -default "present" -validateset "absent","present"
  $g_h.category = Get-AnsibleParam -obj $g_h -name "category" -type "str" -validateset "Distribution","Security" -default "Security"
  $g_h.scope = Get-AnsibleParam -obj $g_h -name "scope" -type "str" -validateset "DomainLocal","Global","Universal" -failifempty $true
  $g_h.clear_attributes = Get-AnsibleParam -obj $g_h -name "clear_attributes" -type "list" -default @()

  # attrs
  if ($g_h.containsKey("attributes")) {
    $a_h = @{}
    $g_h.attributes.psobject.properties | Foreach { $a_h[$_.Name] = $_.Value }
    $g_h.attributes = $a_h
  } else {
    $g_h.attributes = @()
  }

  # object name
  $objname = $g_h.sAMAccountName
  if ($default_name_attr -ne "sAMAccountName" -and $g_h.attributes -and $g_h.attributes.containsKey($default_name_attr)) {
    $objname = $g_h.attributes[$default_name_attr]
  }
  $g_h.name = Get-AnsibleParam -obj $g_h -name "name" -type "str" -default $objname

  # membership
  $g_h.add_members = Get-AnsibleParam -obj $g_h -name "add_members" -type "list"
  $g_h.remove_members = Get-AnsibleParam -obj $g_h -name "remove_members" -type "list"
  $g_h.members = Get-AnsibleParam -obj $g_h -name "members" -type "list"

  $groups += $g_h
}


if (-not (Get-Module -Name ActiveDirectory -ListAvailable)) {
  Fail-Json $result "Failed to import ActiveDirectory PowerShell module. This module should be run on a domain controller, and the ActiveDirectory module must be available."
}
Import-Module ActiveDirectory


$extra_args = @{}
if ($domain_username -ne $null) {
    $domain_password = ConvertTo-SecureString $domain_password -AsPlainText -Force
    $credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $domain_username, $domain_password
    $extra_args.Credential = $credential
}
if ($domain_server -ne $null) {
    $extra_args.Server = $domain_server
}

try {
  foreach ($group in $groups) {
    if ($group.state -eq "absent") {
      # Ensure group does not exist
      try {
        $g = Get-ADGroup -Identity $group.sAMAccountName -Properties * @extra_args
      } catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        $g = $null
      }
      if ($g -ne $null) {
        Remove-ADGroup $g -Confirm:$false -WhatIf:$check_mode @extra_args
        Update-Result $g.sAMAccountName "state" "present" "absent"
      }
    } elseif ($group.state -eq "present") {
      # validate that path is an actual path
      try {
          Get-ADObject -Identity $group.path @extra_args | Out-Null
      } catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
          Fail-Json $result "the group path $group.path does not exist, please specify a valid LDAP path"
      }

      # Get group object or create new
      try {
        $g = Get-ADGroup -Identity $group.sAMAccountName -Properties * @extra_args
      } catch {
        New-ADGroup -Name $group.name -sAMAccountName $group.sAMAccountName -Path $group.path -GroupScope $group.scope -GroupCategory $group.category  -WhatIf:$check_mode @extra_args
        Update-Result $group.sAMAccountName "state" "absent" "present"
        $g = Get-ADGroup -Identity $group.sAMAccountName -Properties * @extra_args
      }

      # change category and scope
      if ($group.scope -ne $g.GroupScope) {
        if ($g.GroupScope -eq "Global" -and $group.scope -eq "DomainLocal") {
          Set-ADGroup -Identity $group.sAMAccountName -GroupScope universal -WhatIf:$check_mode @extra_args
          Set-ADGroup -Identity $group.sAMAccountName -GroupScope domainlocal -WhatIf:$check_mode @extra_args
        } elseif ($g.GroupScope -eq "DomainLocal" -and $group.scope -eq "Global") {
          Set-ADGroup -Identity $group.sAMAccountName -GroupScope universal -WhatIf:$check_mode @extra_args
          Set-ADGroup -Identity $group.sAMAccountName -GroupScope global -WhatIf:$check_mode @extra_args
        } else {
          Set-ADGroup -Identity $group.sAMAccountName -GroupScope $group.scope -WhatIf:$check_mode @extra_args
        }
        Update-Result $group.sAMAccountName "scope" $g.GroupScope $group.scope
        $g = Get-ADGroup -Identity $group.sAMAccountName -Properties * @extra_args
      }
      if ($group.category -ne $g.GroupCategory) {
        Set-ADGroup -Identity $group.sAMAccountName -GroupCategory $group.category -WhatIf:$check_mode @extra_args
        Update-Result $group.sAMAccountName "category" $g.GroupCategory $group.category
        $g = Get-ADGroup -Identity $group.sAMAccountName -Properties * @extra_args
      }

      # Set additional attributes
      $set_args = $extra_args.Clone()
      $run_change = $false

      $add_attributes = @{}
      $replace_attributes = @{}
      $clear_attributes = @()
      foreach ($attribute in $group.attributes.GetEnumerator()) {
        $attribute_name = $attribute.Name
        $attribute_value = $attribute.Value
        $valid_property = [bool]($g.PSobject.Properties.name -eq $attribute_name)
        if ($valid_property) {
          $existing_value = $g.$attribute_name
          if ($existing_value -cne $attribute_value) {
            $replace_attributes[$attribute_name] = $attribute_value
            Update-Result $group.sAMAccountName $attribute_name $g.$attribute_name $attribute_value
          }
          if ($group.clear_attributes -and $group.clear_attributes.contains($attribute_name)) {
            $clear_attributes += $attribute_name
            Update-Result $group.sAMAccountName $attribute_name $attribute_value $null
          }
        } else {
          $add_attributes[$attribute_name] = $attribute_value
          Update-Result $group.sAMAccountName $attribute_name $null $attribute_value
        }
      }

      if ($add_attributes.Count -gt 0) {
        $set_args.Add = $add_attributes
        $run_change = $true
      }
      if ($replace_attributes.Count -gt 0) {
        $set_args.Replace = $replace_attributes
        $run_change = $true
      }
      if ($clear_attributes.Count -gt 0) {
        $set_args.Clear = $clear_attributes
        $run_change = $true
      }

      if ($run_change) {
        try {
          $g = $g | Set-ADGroup -WhatIf:$check_mode -PassThru @set_args
        } catch {
          Fail-Json $result "failed to change group $($group.sAMAccountName): $($_.Exception.Message)"
        }
      }

      # rename object
      if ($group.name -ne $g.name) {
        $result.changed = $true
        Update-Result $group.sAMAccountName "renamed" $g.name $group.name
        $g = $g | Rename-ADObject -NewName $group.name -WhatIf:$check_mode -PassThru @extra_args
      }

      # move object
      $existing_path = $g.distinguishedName -replace ("^CN="+$g.name+",")
      if ($existing_path -ne $group.path) {
        $result.changed = $true
        Update-Result $group.sAMAccountName "path" $existing_path $group.path
        $g = $g | Move-ADObject -Targetpath $group.path -WhatIf:$check_mode -PassThru @extra_args
      }

      # Add members
      if ($null -ne $group.add_members) {
        $members = Get-ADGroupMember -Identity $group.sAMAccountName @extra_args | select -ExpandProperty "sAMAccountName"
        foreach ($m in $group.add_members) {
          if (-not ($members -contains $m)) {
            Add-ADGroupMember -Identity $group.sAMAccountName -Members $m -Confirm:$false -WhatIf:$check_mode @extra_args
            Update-Result $group.sAMAccountName "membership: ${m}" $false $true
          }
        }
      }

      # Remove members
      if ($null -ne $group.remove_members) {
        $members = Get-ADGroupMember -Identity $group.sAMAccountName @extra_args | select -ExpandProperty "sAMAccountName"
        foreach ($m in $group.remove_members) {
          if ($members -contains $m) {
            Remove-ADGroupMember -Identity $group.sAMAccountName -Members $m -Confirm:$false -WhatIf:$check_mode @extra_args
            Update-Result $group.sAMAccountName "membership: ${m}" $true $false
          }
        }
      }

      # Sync members
      if ($null -ne $group.members) {
        $members = Get-ADGroupMember -Identity $group.sAMAccountName @extra_args | select -ExpandProperty "sAMAccountName"
        foreach ($m in $group.members) {
          if (-not ($members -contains $m)) {
            Add-ADGroupMember -Identity $group.sAMAccountName -Members $m -Confirm:$false -WhatIf:$check_mode @extra_args
            Update-Result $group.sAMAccountName "membership: ${m}" $false $true
          }
        }

        foreach ($m in $members) {
          if (-not ($group.members -contains $m)) {
            Remove-ADGroupMember -Identity $group.sAMAccountName -Members $m -Confirm:$false -WhatIf:$check_mode @extra_args
            Update-Result $group.sAMAccountName "membership: ${m}" $true $false
          }
        }
      }

    }
  }
} catch {
  Fail-Json $result $_.Exception.Message
}
Exit-Json $result
