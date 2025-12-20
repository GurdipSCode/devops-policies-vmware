package vmware.naming

import future.keywords.in
import future.keywords.if
import future.keywords.contains

# VM naming pattern: <env>-<app>-<role>-<number>
vm_name_pattern := `^[a-z]{3,4}-[a-z]+-[a-z]+-[0-9]{2,3}$`

# Datastore naming pattern: <site>-<type>-<number>
datastore_name_pattern := `^[A-Z]{2,4}-[A-Z]+-[0-9]{2,3}$`

# Network naming pattern: <env>-<vlan>-<purpose>
network_name_pattern := `^[A-Z]+-VLAN[0-9]+-[A-Z]+$`

# Environment prefixes
env_prefixes := ["dev-", "stg-", "uat-", "prd-", "prod-", "tst-", "dmz-"]

# Deny VMs with invalid naming convention
deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "vsphere_virtual_machine"
    resource.change.actions[_] in ["create", "update"]
    
    after := resource.change.after
    name := lower(after.name)
    not regex.match(vm_name_pattern, name)
    
    msg := sprintf(
        "vSphere VM '%s' name must match pattern <env>-<app>-<role>-<number> (e.g., prd-web-app-01)",
        [resource.address]
    )
}

# Deny VMs without environment prefix
deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "vsphere_virtual_machine"
    resource.change.actions[_] in ["create", "update"]
    
    after := resource.change.after
    name := lower(after.name)
    not has_env_prefix(name)
    
    msg := sprintf(
        "vSphere VM '%s' must have environment prefix (dev-, stg-, uat-, prd-, tst-, dmz-)",
        [resource.address]
    )
}

has_env_prefix(name) if {
    prefix := env_prefixes[_]
    startswith(name, prefix)
}

# Deny VMs with spaces in name
deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "vsphere_virtual_machine"
    resource.change.actions[_] in ["create", "update"]
    
    after := resource.change.after
    contains(after.name, " ")
    
    msg := sprintf(
        "vSphere VM '%s' name cannot contain spaces",
        [resource.address]
    )
}

# Deny VMs with underscores (use hyphens)
warn contains msg if {
    resource := input.resource_changes[_]
    resource.type == "vsphere_virtual_machine"
    resource.change.actions[_] in ["create", "update"]
    
    after := resource.change.after
    contains(after.name, "_")
    
    msg := sprintf(
        "vSphere VM '%s' name should use hyphens instead of underscores",
        [resource.address]
    )
}

# Deny folders with generic names
deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "vsphere_folder"
    resource.change.actions[_] in ["create", "update"]
    
    after := resource.change.after
    name := lower(after.path)
    generic := ["test", "temp", "new", "folder", "vm", "vms"]
    segments := split(name, "/")
    segment := segments[_]
    segment in generic
    
    msg := sprintf(
        "vSphere folder '%s' uses generic name; use descriptive naming",
        [resource.address]
    )
}

# Deny resource pools with generic names
deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "vsphere_resource_pool"
    resource.change.actions[_] in ["create", "update"]
    
    after := resource.change.after
    name := lower(after.name)
    generic := ["pool", "default", "resources", "test"]
    name in generic
    
    msg := sprintf(
        "vSphere resource pool '%s' cannot use generic name '%s'",
        [resource.address, after.name]
    )
}

# Deny port groups without VLAN in name
warn contains msg if {
    resource := input.resource_changes[_]
    resource.type == "vsphere_distributed_port_group"
    resource.change.actions[_] in ["create", "update"]
    
    after := resource.change.after
    name := upper(after.name)
    not contains(name, "VLAN")
    
    msg := sprintf(
        "vSphere port group '%s' should include VLAN identifier in name",
        [resource.address]
    )
}

# Deny VMs with names longer than 80 characters (vSphere limit)
deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "vsphere_virtual_machine"
    resource.change.actions[_] in ["create", "update"]
    
    after := resource.change.after
    count(after.name) > 80
    
    msg := sprintf(
        "vSphere VM '%s' name exceeds 80 character limit (%d chars)",
        [resource.address, count(after.name)]
    )
}

# Deny tags without category prefix
warn contains msg if {
    resource := input.resource_changes[_]
    resource.type == "vsphere_tag"
    resource.change.actions[_] in ["create", "update"]
    
    after := resource.change.after
    not contains(after.name, "-")
    
    msg := sprintf(
        "vSphere tag '%s' should follow <category>-<value> naming convention",
        [resource.address]
    )
}
