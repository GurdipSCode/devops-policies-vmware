package lib.helpers

# Check if a resource is being created or updated
is_create_or_update(resource) {
    resource.change.actions[_] == "create"
}

is_create_or_update(resource) {
    resource.change.actions[_] == "update"
}

# Get the resource after changes
get_resource_after(resource) = after {
    after := resource.change.after
}

# Check if a value is empty
is_empty(value) {
    value == null
}

is_empty(value) {
    value == ""
}

is_empty(value) {
    count(value) == 0
}

# Check if resource has specific tag
has_tag(resource, key) {
    resource.change.after.tags[key]
}

# Get tag value
get_tag(resource, key) = value {
    value := resource.change.after.tags[key]
}

# Check if string matches pattern
matches_pattern(str, pattern) {
    regex.match(pattern, str)
}

# Validate naming convention
valid_name(name, prefix) {
    startswith(name, prefix)
}

# Check for sensitive patterns in strings
contains_sensitive_pattern(str) {
    sensitive_patterns := ["password", "secret", "key", "token", "credential"]
    pattern := sensitive_patterns[_]
    contains(lower(str), pattern)
}
