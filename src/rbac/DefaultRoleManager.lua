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

require "src/rbac/DomainRoles"

DefaultRoleManager = {
    defaultDomain = 'casbin::default',
    allDomains,
    maxHierarchyLevel,

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
function DefaultRoleManager:DefaultRoleManager(maxHierarchyLevel, matchingFunc, domainMatchingFunc)
    allDomains = {}
    self.maxHierarchyLevel = maxHierarchyLevel
    self.matchingFunc = matchingFunc
    self.domainMatchingFunc = domainMatchingFunc
end

function domainName(...)
    arg = {...}
    if #arg == 0  then
        return defaultDomain
    else
        return arg[1]
    end
end

--[[
     * Build temporary roles when a domain matching function is defined, else the domain or default
     * roles.
     *
     * @param domain eventual domain
     * @return matched domain roles or domain roles
]]
function getMatchingDomainRoles(...)
    domain = {...}
    if domainMatchingFunc ~= nil then
        return generateTempRoles(domainName(domain))
    else
        return getOrCreateDomainRoles(domainName(domain))
    end
end

function generateTempRoles(domain)
    local flag = 0
    for k, v in pairs(allDomains) do
        if k == domain then
            flag = 1
        end
    end
    if flag == 0 then
        allDomains[domain] = DomainRoles:new()
    end

    allRoles = DomainRoles:new()
    local patternDomains = getPatternMatchedDomainNames(domain)

    for i=1, #patternDomains do
        local flag = 0
        for k, v in pairs(allDomains) do
            if k == patternDomains[i] then
                flag = 1
            end
        end
        if flag == 0 then
            allDomains[patternDomains[i]] = DomainRoles:new()
        end
        createTempRolesForDomain(allRoles, patternDomains[i])
    end

    return allRoles
end

function getPatternMatchedDomainNames(domain)
    local patternDomains = {}
    table.insert(patternDomains, domain)

    if domainMatchingFunc ~= nil then
        for k, v in pairs(allDomains) do
            local f = loadstring (tostring(domainMatchingFunc)) --  domainMatchingFunc.test(domain, k)
            if f() then
                table.insert(patternDomains, k)
            end
        end
    end

    return patternDomains
end

function createTempRolesForDomain(allRoles, domainName)
    --for roleName, role in pairs(allDomains[domainName]) do
    --    role1 = allRoles:creatRole(role:getName(), matchingFunc)
    --
    --end

end

--  * clear clears all stored data and resets the role manager to the initial state.
function DefaultRoleManager:clear()

end

function getOrCreateDomainRoles(domain)

end

--[[
     * addLink adds the inheritance link between role: name1 and role: name2. aka role: name1
     * inherits role: name2. domain is a prefix to the roles.
]]
function DefaultRoleManager:addLink(name1, name2, ...)

end

--[[
     * deleteLink deletes the inheritance link between role: name1 and role: name2. aka role: name1
     * does not inherit role: name2 any more. domain is a prefix to the roles.
]]
function DefaultRoleManager:deleteLink(name1, name2, ...)

end

--       * hasLink determines whether role: name1 inherits role: name2. domain is a prefix to the roles.
function DefaultRoleManager:hasLink(name1, name2, ...)
    local domain = {...}
    if #domain > 1 then
        error("error: domain should be 1 parameter")
    end
    if #domain >= 1 and domain[1] == "*" then
        error("error: domain can't be *")
    end

    if name1 == name2 then
        return true
    end

    if domainMatchingFunc ~= nil then
        allRoles = generateTempRoles(domainName(domain))
    else
        allRoles = getOrCreateDomainRoles(domainName(domain))
    end

    if not(allRoles:hasRole(name1, matchingFunc)) or not(allRoles:hasRole(name2, matchingFunc)) then
        return false
    end

    role1 = allRoles:createRole(name1, matchingFunc)
    return role1:hasRole(name2, maxHierarchyLevel)
end

--  * getRoles gets the roles that a subject inherits. domain is a prefix to the roles.
function DefaultRoleManager:getRoles(name, ...)

end

--  * getUsers gets the users that inherits a subject.
function DefaultRoleManager:getUsers(name, ...)

end

--  * printRoles prints all the roles to log.
function DefaultRoleManager:printRoles(name, ...)

end

return DefaultRoleManager