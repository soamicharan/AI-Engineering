from functools import reduce
from collections import defaultdict

roles = [
    {
        "name": "access-manager",
        "modulePermsiion": {
            "role_management": ["read", "write"],
            "content_management": ["update"],
        },
    },
    {
        "name": "content-manager",
        "modulePermsiion": {"content_management": ["read", "write"]},
    },
]
PERMISSION_ENCODING = {"read": 1, "write": 2, "update": 4}
PERMISSION_DECODE = {
    1: "read",
    2: "write",
    3: ["read", "write"],
    4: "update",
    5: ["read", "update"],
    6: ["write", "update"],
    7: ["read", "write", "update"],
}

def role_encode(roles_data):
    data = {}
    for role in roles_data:
        data[role["name"]] = {
            module: reduce(
                lambda x=0, y=0: PERMISSION_ENCODING.get(x, 0)
                | PERMISSION_ENCODING.get(y, 0),
                permission,
            )
            if len(permission) > 1
            else PERMISSION_ENCODING.get(permission[0], 0)
            for module, permission in role.get("modulePermsiion", {}).items()
        }
    return data


ROLE_DATA = role_encode(roles)

def get_permission(user):
    data = {"name": user["name"]}
    module_permissions = defaultdict(int)
    for role in user["roles"]:
        for module, permission in ROLE_DATA[role].items():
            module_permissions[module] |= permission
    
    for module in module_permissions:
        module_permissions[module] = PERMISSION_DECODE[module_permissions[module]]
    
    return {**data, "modulePermsiion": dict(module_permissions)}


output = {
    "name": "meraj",
    "modulePermsiion": {
        "content_management": ["read", "write", "update"],
        "role_management": ["read", "write"],
    },
}

users = {"name": "meraj", "roles": ["access-manager", "content-manager"]}
assert output == get_permission(users)
