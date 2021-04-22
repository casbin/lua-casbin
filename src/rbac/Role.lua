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

--  * Role represents the data structure for a role in RBAC.
Role = {}

function Role:new(name)
    local o = {}
    setmetatable(o, self)
    self.__index = self
    self.name = name
    self.roles = {}
    return o
end

function Role:addRole(role)
    for _, r in pairs(self.roles) do
        if r.name == role.name then
            return
        end
    end

    table.insert(self.roles, role)
end

function Role:deleteRole(role)
    for k, r in pairs(self.roles) do
        if r.name == role.name then
            table.remove(self.roles, k)
        end
    end
end

function Role:hasRole(name, hierarchyLevel, matchingFunc)
    if self.name == name then
        return true
    end
    if self:hasDirectRole(name, matchingFunc) then
        return true
    end

    if hierarchyLevel <= 0 then
        return false
    end

    for _, r in pairs(self.roles) do
        if r:hasRole(name, hierarchyLevel - 1, matchingFunc) then
            return true
        end
    end

    return false
end

function Role:hasDirectRole(name, matchingFunc)
    if matchingFunc then
        for _, r in pairs(self.roles) do
            if matchingFunc(name, r.name) then
                return true
            end
        end
    else
        for _, r in pairs(self.roles) do
            if r.name == name then
                return true
            end
        end
    end

    return false
end

function Role:toString()
    local names = ""
    names = self.name + " < "
    
    for k, r in pairs(self.rules) do
        if k==1 then 
            names = names + r.name
        else
            names = names + ", " + r.name
        end
    end
    return names
end

function Role:getRoles()
    local names = {}
    for _, r in pairs(self.roles) do
        table.insert(names, r.name)
    end
    return names
end

return Role
