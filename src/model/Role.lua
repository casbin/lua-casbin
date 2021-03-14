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
    for i=1, #self.roles do
        if self.roles[i].name == role.name then
            return
        end
    end

    table.insert(self.roles, role)
end

function Role:deleteRole(role)
    toRemove = {}
    for i=1, #self.roles do
        if self.roles[i].name == role.name then
            table.remove(self.roles, i)
        end
    end
end

function Role:hasRole(name, hierarchyLevel)
    if self.name == name then
        return true
    end
    if hierarchyLevel <= 0 then
        return false
    end
    res = false
    for i=1, #self.roles do
        res = res or self.roles[i]:hasRole(name, hierarchyLevel - 1)
    end
    return res
end

function Role:hasDirectRole(name)
    for i=1, #self.roles do
        if self.roles[i] == name then
            return true
        end
    end

    return false
end

function Role:toString()

    return
end

function Role:getRoles()
    names = {}
    for i=1, #self.roles do
        table.insert(names, self.roles[i])
    end
    return names
end

return Role