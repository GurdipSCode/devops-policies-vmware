package vmware.security

import future.keywords.in
import future.keywords.if
import future.keywords.contains

# Deny VMs without encryption in production
deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "vsphere_virtual_machine"
    resource.change.actions[_] in ["create", "update"]
    
    after := resource.change.after
    contains(lower(after.name), "prod")
    not after.vvtd_enabled
    
    msg := sprintf(
        "Production vSphere VM '%s' should have vVTPM enabled for encryption support",
        [resource.address]
    )
}

# Deny VMs with CPU hot-add in production (security risk)
deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "vsphere_virtual_machine"
    resource.change.actions[_] in ["create", "update"]
    
    after := resource.change.after
    contains(lower(after.name), "prod")
    after.cpu_hot_add_enabled == true
    
    msg := sprintf(
        "Production vSphere VM '%s' should not have CPU hot-add enabled for security",
        [resource.address]
    )
}

# Deny VMs with memory hot-add in production (security risk)
deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "vsphere_virtual_machine"
    resource.change.actions[_] in ["create", "update"]
    
    after := resource.change.after
    contains(lower(after.name), "prod")
    after.memory_hot_add_enabled == true
    
    msg := sprintf(
        "Production vSphere VM '%s' should not have memory hot-add enabled for security",
        [resource.address]
    )
}

# Deny VMs without secure boot when using EFI
deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "vsphere_virtual_machine"
    resource.change.actions[_] in ["create", "update"]
    
    after := resource.change.after
    after.firmware == "efi"
    after.efi_secure_boot_enabled != true
    
    msg := sprintf(
        "vSphere VM '%s' with EFI firmware must have secure boot enabled",
        [resource.address]
    )
}

# Deny VMs connected to default network
deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "vsphere_virtual_machine"
    resource.change.actions[_] in ["create", "update"]
    
    after := resource.change.after
    network := after.network_interface[_]
    contains(lower(network.network_id), "vm network")
    
    msg := sprintf(
        "vSphere VM '%s' should not use default 'VM Network'; use dedicated network",
        [resource.address]
    )
}

# Deny distributed port groups without security policy
deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "vsphere_distributed_port_group"
    resource.change.actions[_] in ["create", "update"]
    
    after := resource.change.after
    not after.security_policy
    
    msg := sprintf(
        "vSphere distributed port group '%s' must have a security policy configured",
        [resource.address]
    )
}

# Deny port groups allowing promiscuous mode
deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "vsphere_distributed_port_group"
    resource.change.actions[_] in ["create", "update"]
    
    after := resource.change.after
    after.security_policy[0].allow_promiscuous == true
    
    msg := sprintf(
        "vSphere distributed port group '%s' must not allow promiscuous mode",
        [resource.address]
    )
}

# Deny port groups allowing MAC changes
deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "vsphere_distributed_port_group"
    resource.change.actions[_] in ["create", "update"]
    
    after := resource.change.after
    after.security_policy[0].allow_mac_changes == true
    
    msg := sprintf(
        "vSphere distributed port group '%s' should not allow MAC address changes",
        [resource.address]
    )
}

# Deny port groups allowing forged transmits
deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "vsphere_distributed_port_group"
    resource.change.actions[_] in ["create", "update"]
    
    after := resource.change.after
    after.security_policy[0].allow_forged_transmits == true
    
    msg := sprintf(
        "vSphere distributed port group '%s' should not allow forged transmits",
        [resource.address]
    )
}

# Deny VMs without anti-affinity rules in HA clusters
warn contains msg if {
    resource := input.resource_changes[_]
    resource.type == "vsphere_virtual_machine"
    resource.change.actions[_] in ["create", "update"]
    
    after := resource.change.after
    contains(lower(after.name), "prod")
    not after.host_system_id
    
    # Check if there's a corresponding anti-affinity rule
    not has_anti_affinity_rule(after.name)
    
    msg := sprintf(
        "Production vSphere VM '%s' should have anti-affinity rules for HA",
        [resource.address]
    )
}

has_anti_affinity_rule(vm_name) if {
    resource := input.resource_changes[_]
    resource.type == "vsphere_compute_cluster_vm_anti_affinity_rule"
    contains(resource.address, vm_name)
}

# Deny VMs with unrestricted disk access
deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "vsphere_virtual_machine"
    resource.change.actions[_] in ["create", "update"]
    
    after := resource.change.after
    disk := after.disk[_]
    disk.disk_mode == "independent_persistent"
    
    msg := sprintf(
        "vSphere VM '%s' disk should not use independent_persistent mode without justification",
        [resource.address]
    )
}

# Deny content library without authentication
deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "vsphere_content_library"
    resource.change.actions[_] in ["create", "update"]
    
    after := resource.change.after
    after.publication[0].published == true
    not after.publication[0].authentication_method
    
    msg := sprintf(
        "vSphere content library '%s' with publication enabled must have authentication",
        [resource.address]
    )
}

# Warn on VMs without VMware Tools
warn contains msg if {
    resource := input.resource_changes[_]
    resource.type == "vsphere_virtual_machine"
    resource.change.actions[_] in ["create", "update"]
    
    after := resource.change.after
    after.sync_time_with_host != true
    
    msg := sprintf(
        "vSphere VM '%s' should enable sync_time_with_host for time synchronization",
        [resource.address]
    )
}
