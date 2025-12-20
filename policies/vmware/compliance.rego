package vmware.compliance

import future.keywords.in
import future.keywords.if
import future.keywords.contains

# Required tags for all VMs
required_tags := ["environment", "owner", "cost_center", "application"]

# Deny VMs without required tags
deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "vsphere_virtual_machine"
    resource.change.actions[_] in ["create", "update"]
    
    after := resource.change.after
    not after.tags
    
    msg := sprintf(
        "vSphere VM '%s' must have tags assigned",
        [resource.address]
    )
}

# Deny VMs missing specific required tags
deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "vsphere_virtual_machine"
    resource.change.actions[_] in ["create", "update"]
    
    after := resource.change.after
    after.tags
    tag := required_tags[_]
    not has_tag_category(after.tags, tag)
    
    msg := sprintf(
        "vSphere VM '%s' missing required tag category: %s",
        [resource.address, tag]
    )
}

has_tag_category(tags, category) if {
    tag := tags[_]
    contains(lower(tag), category)
}

# Deny VMs without resource pool assignment
deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "vsphere_virtual_machine"
    resource.change.actions[_] in ["create", "update"]
    
    after := resource.change.after
    not after.resource_pool_id
    
    msg := sprintf(
        "vSphere VM '%s' must be assigned to a resource pool",
        [resource.address]
    )
}

# Deny VMs without folder organization
warn contains msg if {
    resource := input.resource_changes[_]
    resource.type == "vsphere_virtual_machine"
    resource.change.actions[_] in ["create", "update"]
    
    after := resource.change.after
    not after.folder
    
    msg := sprintf(
        "vSphere VM '%s' should be organized in a folder",
        [resource.address]
    )
}

# Deny VMs with excessive CPU allocation
deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "vsphere_virtual_machine"
    resource.change.actions[_] in ["create", "update"]
    
    after := resource.change.after
    after.num_cpus > 32
    
    msg := sprintf(
        "vSphere VM '%s' exceeds maximum allowed CPUs (32). Requested: %d",
        [resource.address, after.num_cpus]
    )
}

# Deny VMs with excessive memory allocation
deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "vsphere_virtual_machine"
    resource.change.actions[_] in ["create", "update"]
    
    after := resource.change.after
    after.memory > 262144  # 256 GB
    
    msg := sprintf(
        "vSphere VM '%s' exceeds maximum allowed memory (256GB). Requested: %dMB",
        [resource.address, after.memory]
    )
}

# Deny VMs without CPU/memory reservations in production
warn contains msg if {
    resource := input.resource_changes[_]
    resource.type == "vsphere_virtual_machine"
    resource.change.actions[_] in ["create", "update"]
    
    after := resource.change.after
    contains(lower(after.name), "prod")
    not after.cpu_reservation
    
    msg := sprintf(
        "Production vSphere VM '%s' should have CPU reservation configured",
        [resource.address]
    )
}

# Deny datastores without VMFS 6
warn contains msg if {
    resource := input.resource_changes[_]
    resource.type == "vsphere_vmfs_datastore"
    resource.change.actions[_] in ["create", "update"]
    
    after := resource.change.after
    after.vmfs_version != 6
    
    msg := sprintf(
        "vSphere datastore '%s' should use VMFS 6",
        [resource.address]
    )
}

# Deny VMs without annotation/notes
warn contains msg if {
    resource := input.resource_changes[_]
    resource.type == "vsphere_virtual_machine"
    resource.change.actions[_] in ["create", "update"]
    
    after := resource.change.after
    not after.annotation
    
    msg := sprintf(
        "vSphere VM '%s' should have an annotation describing its purpose",
        [resource.address]
    )
}

# Deny clusters without HA enabled
deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "vsphere_compute_cluster"
    resource.change.actions[_] in ["create", "update"]
    
    after := resource.change.after
    after.ha_enabled != true
    
    msg := sprintf(
        "vSphere cluster '%s' must have HA enabled",
        [resource.address]
    )
}

# Deny clusters without DRS enabled
warn contains msg if {
    resource := input.resource_changes[_]
    resource.type == "vsphere_compute_cluster"
    resource.change.actions[_] in ["create", "update"]
    
    after := resource.change.after
    after.drs_enabled != true
    
    msg := sprintf(
        "vSphere cluster '%s' should have DRS enabled for load balancing",
        [resource.address]
    )
}

# Deny VMs on specific datastores (e.g., local storage in production)
deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "vsphere_virtual_machine"
    resource.change.actions[_] in ["create", "update"]
    
    after := resource.change.after
    contains(lower(after.name), "prod")
    disk := after.disk[_]
    contains(lower(disk.datastore_id), "local")
    
    msg := sprintf(
        "Production vSphere VM '%s' should not use local datastores",
        [resource.address]
    )
}
