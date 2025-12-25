# OPA Policies for vSphere Terraform Provider
# Enforces organizational standards for VM deployments

package terraform.vsphere

import rego.v1
import input.plan as tfplan

# ============================================================================
# CONFIGURATION - Customize these values for your organization
# ============================================================================

# Allowed VM configurations
allowed_cpu_counts := [1, 2, 4, 8, 16]
max_memory_mb := 65536  # 64 GB
max_disk_size_gb := 2048  # 2 TB per disk
max_disks_per_vm := 8

# Approved resources
allowed_datacenters := ["dc-prod", "dc-dev", "dc-staging"]
allowed_clusters := ["cluster-prod", "cluster-dev", "cluster-staging"]
allowed_datastores := ["datastore-prod-01", "datastore-prod-02", "datastore-dev-01", "vsanDatastore"]
allowed_networks := ["VM Network", "Production-VLAN-100", "Development-VLAN-200", "Management-VLAN-10"]
allowed_templates := ["ubuntu-22.04-template", "rhel-9-template", "windows-2022-template"]

# Required tags
required_tag_categories := ["environment", "owner", "cost-center"]

# VM naming pattern (regex)
vm_name_pattern := "^[a-z]{2,4}-[a-z]+-[0-9]{2,3}$"  # e.g., "prod-web-01"

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

# Get all resources of a specific type that are being created or updated
resources_by_type(type) := resources if {
    resources := [r |
        r := tfplan.resource_changes[_]
        r.type == type
        r.change.actions[_] in ["create", "update"]
    ]
}

# Get vSphere virtual machines
vsphere_vms := resources_by_type("vsphere_virtual_machine")

# ============================================================================
# VM CPU POLICIES
# ============================================================================

# Deny VMs with non-approved CPU counts
deny contains msg if {
    vm := vsphere_vms[_]
    num_cpus := vm.change.after.num_cpus
    not num_cpus in allowed_cpu_counts
    msg := sprintf(
        "VM '%s' has %d CPUs. Allowed CPU counts: %v",
        [vm.address, num_cpus, allowed_cpu_counts]
    )
}

# ============================================================================
# VM MEMORY POLICIES
# ============================================================================

# Deny VMs with memory exceeding maximum
deny contains msg if {
    vm := vsphere_vms[_]
    memory := vm.change.after.memory
    memory > max_memory_mb
    msg := sprintf(
        "VM '%s' requests %d MB memory. Maximum allowed: %d MB",
        [vm.address, memory, max_memory_mb]
    )
}

# Warn on large memory allocations (over 32GB)
warn contains msg if {
    vm := vsphere_vms[_]
    memory := vm.change.after.memory
    memory > 32768
    memory <= max_memory_mb
    msg := sprintf(
        "VM '%s' requests %d MB memory. Consider if this allocation is necessary.",
        [vm.address, memory]
    )
}

# ============================================================================
# VM DISK POLICIES
# ============================================================================

# Deny VMs with disks exceeding maximum size
deny contains msg if {
    vm := vsphere_vms[_]
    disk := vm.change.after.disk[_]
    disk_size_gb := disk.size / 1024 / 1024 / 1024
    disk_size_gb > max_disk_size_gb
    msg := sprintf(
        "VM '%s' has disk with size %d GB. Maximum allowed: %d GB",
        [vm.address, disk_size_gb, max_disk_size_gb]
    )
}

# Deny VMs with too many disks
deny contains msg if {
    vm := vsphere_vms[_]
    disk_count := count(vm.change.after.disk)
    disk_count > max_disks_per_vm
    msg := sprintf(
        "VM '%s' has %d disks. Maximum allowed: %d disks",
        [vm.address, disk_count, max_disks_per_vm]
    )
}

# Ensure thin provisioning is enabled for non-production
deny contains msg if {
    vm := vsphere_vms[_]
    disk := vm.change.after.disk[_]
    not disk.thin_provisioned
    not contains(vm.change.after.name, "prod")
    msg := sprintf(
        "VM '%s' has thick provisioned disk. Non-production VMs must use thin provisioning.",
        [vm.address]
    )
}

# ============================================================================
# VM NETWORK POLICIES
# ============================================================================

# Deny VMs connected to non-approved networks
deny contains msg if {
    vm := vsphere_vms[_]
    nic := vm.change.after.network_interface[_]
    network_id := nic.network_id
    # Note: You may need to resolve network_id to name via data sources
    # This is a simplified check
    not network_id in allowed_networks
    msg := sprintf(
        "VM '%s' is connected to network '%s'. Allowed networks: %v",
        [vm.address, network_id, allowed_networks]
    )
}

# ============================================================================
# VM NAMING POLICIES
# ============================================================================

# Enforce VM naming convention
deny contains msg if {
    vm := vsphere_vms[_]
    vm_name := vm.change.after.name
    not regex.match(vm_name_pattern, vm_name)
    msg := sprintf(
        "VM '%s' name does not match naming convention. Expected pattern: %s (e.g., 'prod-web-01')",
        [vm.address, vm_name_pattern]
    )
}

# ============================================================================
# VM TEMPLATE POLICIES
# ============================================================================

# Deny VMs not created from approved templates (when using clone)
deny contains msg if {
    vm := vsphere_vms[_]
    clone := vm.change.after.clone[_]
    template_uuid := clone.template_uuid
    # Note: In practice, you'd resolve UUID to template name
    # This shows the pattern for the check
    template_uuid != null
    not template_approved(template_uuid)
    msg := sprintf(
        "VM '%s' uses unapproved template. Contact infrastructure team for approved templates.",
        [vm.address]
    )
}

# Helper to check if template is approved (customize based on your setup)
template_approved(template_uuid) if {
    # In practice, you'd maintain a list of approved template UUIDs
    # or use external data to validate
    template_uuid != ""
}

# ============================================================================
# VM RESOURCE POOL / CLUSTER POLICIES
# ============================================================================

# Ensure VMs specify a resource pool
deny contains msg if {
    vm := vsphere_vms[_]
    not vm.change.after.resource_pool_id
    msg := sprintf(
        "VM '%s' must specify a resource_pool_id",
        [vm.address]
    )
}

# ============================================================================
# VM HARDWARE VERSION POLICIES
# ============================================================================

# Minimum hardware version
min_hardware_version := 19  # vSphere 7.0 U2+

deny contains msg if {
    vm := vsphere_vms[_]
    hw_version := vm.change.after.hardware_version
    hw_version != null
    hw_version < min_hardware_version
    msg := sprintf(
        "VM '%s' uses hardware version %d. Minimum required: %d",
        [vm.address, hw_version, min_hardware_version]
    )
}

# ============================================================================
# VM TOOLS POLICIES
# ============================================================================

# Ensure VMware Tools upgrade policy is set
deny contains msg if {
    vm := vsphere_vms[_]
    not vm.change.after.sync_time_with_host
    msg := sprintf(
        "VM '%s' should have sync_time_with_host enabled for proper time synchronization",
        [vm.address]
    )
}

# ============================================================================
# VM SECURITY POLICIES
# ============================================================================

# Ensure VMs have proper guest customization (for security hardening)
warn contains msg if {
    vm := vsphere_vms[_]
    clone := vm.change.after.clone[_]
    not clone.customize
    msg := sprintf(
        "VM '%s' does not have guest customization configured. This may result in duplicate SIDs/hostnames.",
        [vm.address]
    )
}

# Deny VMs with nested hardware virtualization unless explicitly allowed
deny contains msg if {
    vm := vsphere_vms[_]
    vm.change.after.nested_hv_enabled == true
    not is_nested_hv_allowed(vm.change.after.name)
    msg := sprintf(
        "VM '%s' has nested hardware virtualization enabled. This requires approval.",
        [vm.address]
    )
}

# Helper for nested HV exceptions
is_nested_hv_allowed(name) if {
    contains(name, "nested")
}

is_nested_hv_allowed(name) if {
    contains(name, "hypervisor")
}

# ============================================================================
# VM HIGH AVAILABILITY POLICIES
# ============================================================================

# Ensure production VMs have restart priority set
warn contains msg if {
    vm := vsphere_vms[_]
    contains(vm.change.after.name, "prod")
    not vm.change.after.ha_restart_priority
    msg := sprintf(
        "Production VM '%s' should have ha_restart_priority configured",
        [vm.address]
    )
}

# ============================================================================
# STORAGE POLICIES
# ============================================================================

# Check storage policy assignment
warn contains msg if {
    vm := vsphere_vms[_]
    not vm.change.after.storage_policy_id
    msg := sprintf(
        "VM '%s' does not have a storage policy assigned. Consider assigning appropriate storage policy.",
        [vm.address]
    )
}
