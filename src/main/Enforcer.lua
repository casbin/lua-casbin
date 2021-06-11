--Copyright 2021 The casbin Authors. All Rights Reserved.
--
--Licensed under the Apache License, Version 2.0 (the "License");
--you may not use this file except in compliance with the License.
--You may obtain a copy of the License at
--
--    http://www.apache.org/licenses/LICENSE-2.0
--
--Unless required by applicable law or agreed to in writing, software
--distributed under the License is distributed on an "AS IS" BASIS,
--WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
--See the License for the specific language governing permissions and
--limitations under the License.

require("src.main.ManagementEnforcer")

-- Enforcer = ManagementEnforcer + RBAC API.
Enforcer = {}
setmetatable(Enforcer, ManagementEnforcer)

-- GetRolesForUser gets the roles that a user has.
function Enforcer:GetRolesForUser(name, ...)
    return self.model.model["g"]["g"].RM:getRoles(name, ...)
end

-- GetUsersForRole gets the users that has a role.
function Enforcer:GetUsersForRole(name, ...)
    return self.model.model["g"]["g"].RM:getUsers(name, ...)
end

-- HasRoleForUser determines whether a user has a role.
function Enforcer:HasRoleForUser(name, role, ...)
    local roles = self:GetRolesForUser(name, ...)
    local hasRole = false

    for _, r in pairs(roles) do
        if r == role then
            hasRole = true
            break
        end
    end

    return hasRole
end

-- AddRoleForUser adds role for a user.
-- Returns false if the user already has the roles (aka not affected).
function Enforcer:AddRoleForUser(user, role, ...)
    local args = {...}
    table.insert(args, 1, role)
    table.insert(args, 1, user)
    return self:AddGroupingPolicy(args)
end

-- AddRolesForUser adds roles for a user.
-- Returns false if the user already has the roles (aka not affected).
function Enforcer:AddRolesForUser(user, roles, ...)
    local rules = {}
    for _, role in pairs(roles) do
        local rule = {user, role, ...}
        table.insert(rules, rule)
    end

    return self:AddGroupingPolicies(rules)
end

-- DeleteRoleForUser deletes a role for a user.
-- Returns false if the user does not have the role (aka not affected).
function Enforcer:DeleteRoleForUser(user, role, ...)
    local args = {...}
    table.insert(args, 1, role)
    table.insert(args, 1, user)
    return self:RemoveGroupingPolicy(args)
end

-- DeleteRolesForUser deletes all roles for a user.
-- Returns false if the user does not have any roles (aka not affected).
function Enforcer:DeleteRolesForUser(user, ...)
    if #{...} == 0 then
        return self:RemoveFilteredGroupingPolicy(0, user)
    elseif #{...} > 1 then
        return false
    else
        local domain = {...}
        return self:RemoveFilteredGroupingPolicy(0, user, "", domain[1])
    end
end

-- DeleteUser deletes a user.
-- Returns false if the user does not exist (aka not affected).
function Enforcer:DeleteUser(user)
    local res1 = self:RemoveFilteredGroupingPolicy(0, user)
    local res2 = self:RemoveFilteredPolicy(0, user)
    return res1 or res2
end

-- DeleteRole deletes a role.
-- Returns false if the user does not exist (aka not affected).
function Enforcer:DeleteRole(role)
    local res1 = self:RemoveFilteredGroupingPolicy(1, role)
    local res2 = self:RemoveFilteredPolicy(0, role)
    return res1 or res2
end

-- DeletePermission deletes a permission.
-- Returns false if the permission does not exist (aka not affected).
function Enforcer:DeletePermission(...)
    return self:RemoveFilteredPolicy(1, ...)
end

-- AddPermissionForUser deletes a permission.
-- Returns false if the permission does not exist (aka not affected).
function Enforcer:AddPermissionForUser(user, ...)
    return self:AddPolicy(user, ...)
end

-- DeletePermissionForUser deletes a permission for a user or role.
-- Returns false if the permission does not exist (aka not affected).
function Enforcer:DeletePermissionForUser(user, ...)
    return self:RemovePolicy(user, ...)
end

-- DeletePermissionsForUser deletes permissions for a user or role.
-- Returns false if the permission does not exist (aka not affected).
function Enforcer:DeletePermissionsForUser(user)
    return self:RemoveFilteredPolicy(0, user)
end

-- GetPermissionsForUser gets permissions for a user or role.
function Enforcer:GetPermissionsForUser(user, ...)
    local permissions = {}
    for ptype, ast in pairs(self.model.model["p"]) do
        local args = {}
        for _ = 1, #ast.tokens do
            table.insert(args, "")
        end
        args[1] = user

        if #{...}>0 then
            local index = self:getDomainIndex(ptype)
            if index < #ast.tokens then
                local domain = {...}
                args[index] = domain[1]
            end
        end
        local perm = self:GetFilteredPolicy(0, args)
        for _, v in pairs(perm) do
            table.insert(permissions, v)
        end
    end

    return permissions
end

-- HasPermissionForUser determines whether a user has a permission.
function Enforcer:HasPermissionForUser(user, ...)
    return self:HasPolicy(user, ...)
end

-- GetImplicitRolesForUser gets implicit roles that a user has.
-- Compared to GetRolesForUser(), this function retrieves indirect roles besides direct roles.
-- For example:
-- g, alice, role:admin
-- g, role:admin, role:user
--
-- GetRolesForUser("alice") can only get: ["role:admin"].
-- But GetImplicitRolesForUser("alice") will get: ["role:admin", "role:user"].
function Enforcer:GetImplicitRolesForUser(name, ...)
    local res = {}
	local roleSet = {}
	roleSet[name] = true

	local q = {}
	table.insert(q, name)

	while #q>0 do
        local name = q[1]
        table.remove(q, 1)

        for _, rm in pairs(self.rmMap) do
            local roles = rm:getRoles(name, ...)

            for _, r in pairs(roles) do
                if not roleSet[r] then
                    table.insert(res, r)
                    table.insert(q, r)
                    roleSet[r] = true
                end
            end
        end
    end

	return res
end

-- GetImplicitUsersForRole gets implicit users for a role.
function Enforcer:GetImplicitUsersForRole(name, ...)
    local res = {}
	local roleSet = {}
	roleSet[name] = true

	local q = {}
	table.insert(q, name)

	while #q>0 do
        local name = q[1]
        table.remove(q, 1)

        for _, rm in pairs(self.rmMap) do
            local roles = rm:getUsers(name, ...)

            for _, r in pairs(roles) do
                if not roleSet[r] then
                    table.insert(res, r)
                    table.insert(q, r)
                    roleSet[r] = true
                end
            end
        end
    end

	return res

end

-- GetImplicitPermissionsForUser gets implicit permissions for a user or role.
-- Compared to GetPermissionsForUser(), this function retrieves permissions for inherited roles.
-- For example:
-- p, admin, data1, read
-- p, alice, data2, read
-- g, alice, admin
--
-- GetPermissionsForUser("alice") can only get: [["alice", "data2", "read"]].
-- But GetImplicitPermissionsForUser("alice") will get: [["admin", "data1", "read"], ["alice", "data2", "read"]].
function Enforcer:GetImplicitPermissionsForUser(user, ...)
    local roles = self:GetImplicitRolesForUser(user, ...)

    table.insert(roles, 1, user)

    local res = {}
    local permissions = {}
    for _, role in pairs(roles) do
        permissions = self:GetPermissionsForUser(role, ...)
        for _, v in pairs(permissions) do
            table.insert(res, v)
        end
    end

    return res
end

-- GetImplicitUsersForPermission gets implicit users for a permission.
-- For example:
-- p, admin, data1, read
-- p, bob, data1, read
-- g, alice, admin
--
-- GetImplicitUsersForPermission("data1", "read") will get: ["alice", "bob"].
-- Note: only users will be returned, roles (2nd arg in "g") will be excluded.
function Enforcer:GetImplicitUsersForPermission(...)
    local pSubjects = self:GetAllSubjects()
    local gInherit = self.model:getValuesForFieldInPolicyAllTypes("g", 2)
    local gSubjects = self.model:getValuesForFieldInPolicyAllTypes("g", 1)

    local subjects = {}
    for _, v in pairs(pSubjects) do
        table.insert(subjects, v)
    end
    for _, v in pairs(gSubjects) do
        table.insert(subjects, v)
    end
    subjects = Util.arrayRemoveDuplications(subjects)

    subjects = Util.setSubtract(subjects, gInherit)

    local res = {}
    for _, user in pairs(subjects) do
        local allowed = self:enforce(user, ...)

        if allowed then
            table.insert(res, user)
        end
    end

    return res
end

-- GetDomainsForUser gets all domains
function Enforcer:GetDomainsForUser(user)
    local domains = {}
    for _, rm in pairs(self.rmMap) do
        local domain = self:GetDomains(user)
        for _, v in pairs(domain) do
            table.insert(domains, v)
        end
    end
end

-- GetImplicitResourcesForUser returns all policies that user obtaining in domain
function Enforcer:GetImplicitResourcesForUser(user, ...)
    local permissions = self:GetImplicitPermissionsForUser(user, ...)

    local res = {}
    for _, permission in pairs(permissions) do
        if permission[1] == user then
            table.insert(res, permission)
        else
            local resLocal = {{user}}
            local tokensLength = #permission
            local t = {{}}

            for i = 2, tokensLength do
                local tokens = self:GetImplicitUsersForRole(permission[i], ...)

                table.insert(tokens, permission[i])
                table.insert(t, tokens)
            end

            for i = 2, tokensLength do
                local n = {}
                for _, tokens in pairs(t[i]) do
                    for _, policy in pairs(resLocal) do
                        local t = {}
                        for _, p in pairs(policy) do
                            table.insert(t, p)
                        end
                        table.insert(t, tokens)
                        table.insert(n, t)
                    end
                end
                resLocal = n
            end

            for _, r in pairs(resLocal) do
                table.insert(res, r)
            end
        end
    end

    return res
end

return Enforcer