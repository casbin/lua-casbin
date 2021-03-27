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

--[[
 * Represents all roles in a domain
]]
DomainRoles = {}

function DomainRoles:new()
    local o = {}
    setmetatable(o, self)
    self.__index = self
    self.roles = {}
    return o
end


function DomainRoles:hasRole(name, matchingFunc)
    if matchingFunc ~= nil then
        for r, n in pairs(self.roles) do
            local f = loadstring (tostring(matchingFunc))
            if f() then
                return true
            end
        end
        return false
    else
        if self.roles[name] ~= nil then
            return true
        else
            return false
        end
    end
end

function DomainRoles:createRole(name, matchingFunc)
    local flag = 0
    for k, v in pairs(self.roles) do
        if k == name then
            self.roles = self.roles[name]
            flag = 1
        end
    end
    if flag == 0 then
        self.roles[name] = self.roles:new(name)
        self.roles = self.roles[name]
    end

    if matchingFunc ~= nil then
        for k, v in pairs(self.roles) do
            if isRoleEntryMatchExists(k, name, matchingFunc) then
                self.roles:addRole(k)
            end
        end
    end

    return self.roles
end

function isRoleEntryMatchExists(roleEntryKey, name, matchingFunc)
    if roleEntryKey == name then
        return false
    end
    local f = loadstring (tostring(matchingFunc)) -- matchingFunc.test(name, roleEntryKey)
    if f() then
        return true
    end

    return false
end

function DomainRoles:getOrCreate(name)
    for k, v in pairs(self.roles) do
        if k == name then
            return self.roles[k]
        end
    end

    self.roles[name] = Role:new(name)
    return self.roles[name]
end


return DomainRoles