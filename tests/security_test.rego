package vmware.security_test

import future.keywords.in
import data.vmware.security

# Test: EFI VM without secure boot should be denied
test_deny_efi_without_secure_boot {
    result := security.deny with input as {
        "resource_changes": [{
            "type": "vsphere_virtual_machine",
            "address": "vsphere_virtual_machine.test",
            "change": {
                "actions": ["create"],
                "after": {
                    "name": "prd-web-app-01",
                    "firmware": "efi",
                    "efi_secure_boot_enabled": false
                }
            }
        }]
    }
    count(result) > 0
}

# Test: EFI VM with secure boot should be allowed
test_allow_efi_with_secure_boot {
    result := security.deny with input as {
        "resource_changes": [{
            "type": "vsphere_virtual_machine",
            "address": "vsphere_virtual_machine.test",
            "change": {
                "actions": ["create"],
                "after": {
                    "name": "prd-web-app-01",
                    "firmware": "efi",
                    "efi_secure_boot_enabled": true
                }
            }
        }]
    }
    count(result) == 0
}

# Test: Port group with promiscuous mode should be denied
test_deny_promiscuous_mode {
    result := security.deny with input as {
        "resource_changes": [{
            "type": "vsphere_distributed_port_group",
            "address": "vsphere_distributed_port_group.test",
            "change": {
                "actions": ["create"],
                "after": {
                    "name": "PROD-VLAN100-WEB",
                    "security_policy": [{
                        "allow_promiscuous": true,
                        "allow_mac_changes": false,
                        "allow_forged_transmits": false
                    }]
                }
            }
        }]
    }
    count(result) > 0
}

# Test: Port group with proper security should be allowed
test_allow_secure_port_group {
    result := security.deny with input as {
        "resource_changes": [{
            "type": "vsphere_distributed_port_group",
            "address": "vsphere_distributed_port_group.test",
            "change": {
                "actions": ["create"],
                "after": {
                    "name": "PROD-VLAN100-WEB",
                    "security_policy": [{
                        "allow_promiscuous": false,
                        "allow_mac_changes": false,
                        "allow_forged_transmits": false
                    }]
                }
            }
        }]
    }
    count(result) == 0
}

# Test: Production VM with CPU hot-add should be denied
test_deny_prod_cpu_hot_add {
    result := security.deny with input as {
        "resource_changes": [{
            "type": "vsphere_virtual_machine",
            "address": "vsphere_virtual_machine.prod",
            "change": {
                "actions": ["create"],
                "after": {
                    "name": "prod-db-master-01",
                    "cpu_hot_add_enabled": true
                }
            }
        }]
    }
    count(result) > 0
}

# Test: VM on default network should be denied
test_deny_default_network {
    result := security.deny with input as {
        "resource_changes": [{
            "type": "vsphere_virtual_machine",
            "address": "vsphere_virtual_machine.test",
            "change": {
                "actions": ["create"],
                "after": {
                    "name": "dev-web-app-01",
                    "network_interface": [{
                        "network_id": "VM Network"
                    }]
                }
            }
        }]
    }
    count(result) > 0
}

# Test: Port group without security policy should be denied
test_deny_port_group_no_security {
    result := security.deny with input as {
        "resource_changes": [{
            "type": "vsphere_distributed_port_group",
            "address": "vsphere_distributed_port_group.test",
            "change": {
                "actions": ["create"],
                "after": {
                    "name": "PROD-VLAN100-WEB",
                    "security_policy": null
                }
            }
        }]
    }
    count(result) > 0
}

# Test: Content library with publication but no auth should be denied
test_deny_content_library_no_auth {
    result := security.deny with input as {
        "resource_changes": [{
            "type": "vsphere_content_library",
            "address": "vsphere_content_library.test",
            "change": {
                "actions": ["create"],
                "after": {
                    "name": "shared-templates",
                    "publication": [{
                        "published": true,
                        "authentication_method": null
                    }]
                }
            }
        }]
    }
    count(result) > 0
}

# Test: Valid production VM should be allowed
test_allow_valid_prod_vm {
    result := security.deny with input as {
        "resource_changes": [{
            "type": "vsphere_virtual_machine",
            "address": "vsphere_virtual_machine.prod",
            "change": {
                "actions": ["create"],
                "after": {
                    "name": "prd-web-app-01",
                    "firmware": "efi",
                    "efi_secure_boot_enabled": true,
                    "cpu_hot_add_enabled": false,
                    "memory_hot_add_enabled": false,
                    "sync_time_with_host": true,
                    "network_interface": [{
                        "network_id": "PROD-VLAN100-WEB"
                    }]
                }
            }
        }]
    }
    count(result) == 0
}
