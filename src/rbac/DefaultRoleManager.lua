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

require "src/rbac/Role"

DefaultRoleManager = {
    maxHierarchyLevel = 0
}

--[[
     * In order to use a specific role name matching function, set explicitly the role manager on
     * the Enforcer and rebuild role links (you can optimize by using minimal enforcer constructor).
     *
     * <pre>
     * final Enforcer e = new Enforcer("model.conf");
     * e.setAdapter(new FileAdapter("policies.csv"));
     * e.setRoleManager(new DefaultRoleManager(10, BuiltInFunctions::domainMatch));
     * e.loadPolicy();
     * </pre>
     *
     *
     * @param maxHierarchyLevel the maximized allowed RBAC hierarchy level.
     * @param matchingFunc a matcher for supporting pattern in g
     * @param domainMatchingFunc a matcher for supporting domain pattern in g
]]
function DefaultRoleManager:new(maxHierarchyLevel, matchingFunc, domainMatchingFunc)
    self.allRoles = {}
    self.maxHierarchyLevel = maxHierarchyLevel
    self.matchingFunc = matchingFunc
    self.domainMatchingFunc = domainMatchingFunc
end

function DefaultRoleManager:hasRole(name)
    if self.matchingFunc then
        for key, _ in pairs(self.allRoles) do
            if self.matchingFunc(name, key) then
                return true
            end
        end
    else
        if self.allRoles[name] then
            return true
        end
    end

    return false
end

function DefaultRoleManager:createRole(name)
    if not self.allRoles[name] then
        self.allRoles[name] = Role:new()
    end

    return self.allRoles[name]
end

--  * clear clears all stored data and resets the role manager to the initial state.
function DefaultRoleManager:clear()
    self.allRoles = {}
end

--[[
     * addLink adds the inheritance link between role: name1 and role: name2. aka role: name1
     * inherits role: name2. domain is a prefix to the roles.
]]
function DefaultRoleManager:addLink(name1, name2, ...)
    local domain = {...}
    if #domain == 1 then
        name1 = domain[1] + "::" + name1
        name2 = domain[1] + "::" + name2
    elseif #domain > 1 then
        error("domain should be only 1 parameter")
    else
        domain = nil
    end

    local role1 = self:createRole(name1)
    local role2 = self:createRole(name2)
    role1:addRole(role2)

    if self.matchingFunc then
        for key, role in pairs(self.allRoles) do
            if self.matchingFunc(key, name1) and name1 ~= key then
                self.allRoles[key]:addRole(role1)
            end
            if self.matchingFunc(key, name2) and name2 ~= key then
                self.allRoles[name2]:addRole(role)
            end
            if self.matchingFunc(name1, key) and name1 ~= key then
                self.allRoles[key]:addRole(role1)
            end
            if self.matchingFunc(name2, key) and name2 ~= key then
                self.allRoles[name2]:addRole(role)
            end
        end
    end
end

--[[
     * deleteLink deletes the inheritance link between role: name1 and role: name2. aka role: name1
     * does not inherit role: name2 any more. domain is a prefix to the roles.
]]
function DefaultRoleManager:deleteLink(name1, name2, ...)
    local domain = {...}
    if #domain == 1 then
        name1 = domain[1] + "::" + name1
        name2 = domain[1] + "::" + name2
    elseif #domain > 1 then
        error("domain should be only 1 parameter")
    else
        domain = nil
    end

    if not self:hasRole(name1) or self:hasRole(name2) then
        error("name1 or name2 does not exist")
    end

    local role1 = self:createRole(name1)
    local role2 = self:createRole(name2)
    role1:deleteRole(role2)
end

-- hasLink determines whether role: name1 inherits role: name2. domain is a prefix to the roles.
function DefaultRoleManager:hasLink(name1, name2, ...)
    local domain = {...}
    if #domain == 1 then
        name1 = domain[1] + "::" + name1
        name2 = domain[1] + "::" + name2
    elseif #domain > 1 then
        error("domain should be only 1 parameter")
    else
        domain = nil
    end

    if name1 == name2 then
        return true
    end

    if not (self:hasRole(name1)) or not (self:hasRole(name2)) then
        return false
    end

    if self.matchingFunc then
        for key, role in pairs(self.allRoles) do
            if self.matchingFunc(name1, key) and (role:hasRole(name2, self.maxHierarchyLevel, self.matchingFunc)) then
                return true
            end
        end

        return false
    else
        local role1 = self:createRole(name1)
        return role1:hasRole(name2, self.maxHierarchyLevel)
    end
end

--  * getRoles gets the roles that a subject inherits. domain is a prefix to the roles.
function DefaultRoleManager:getRoles(name, ...)
    local domain = {...}
    if #domain == 1 then
        name = domain[1] + "::" + name
    elseif #domain > 1 then
        error("domain should be only 1 parameter")
    else
        domain = nil
    end

    if not self:hasRole(name) then
        return {}
    end

    local roles = self:createRole(name):getRoles()

    if domain then
        for key, value in pairs(roles) do
            roles[key] = string.sub(value, #domain[1]+3)
        end
    end

    return roles
end

-- getUsers gets the users that inherits a subject.
function DefaultRoleManager:getUsers(name, ...)
    local domain = {...}
    if #domain == 1 then
        name = domain[1] + "::" + name
    elseif #domain > 1 then
        error("domain should be only 1 parameter")
    else
        domain = nil
    end

    local names = {}
    for _, role in pairs(self.allRoles) do
        if role:hasDirectRole(name) then
            if domain then
                table.insert(names, string.sub(role.name, #domain[1]+3))
            else
                table.insert(names, role.name)
            end
        end
    end
end

-- printRoles prints all the roles to log.
function DefaultRoleManager:printRoles(name, ...)
    local lines = {}
    for _, role in pairs(self.allRoles) do
        local text = role:toString()
        if text then table.insert(lines, text) end
    end

    -- TODO: add logger here
end

return DefaultRoleManager
