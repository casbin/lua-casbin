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

require "src/rbac/DefaultRoleManager"

--[[
 * GroupRoleManager is used for authorization if the user's group is the role who has permission,
 * but the group information is in the default format (policy start with "g") and the role information
 * is in named format (policy start with "g2", "g3", ...).
 * e.g.
 * p, admin, domain1, data1, read
 * g, alice, group1
 * g2, group1, admin, domain1
 *
 * As for the previous example, alice should have the permission to read data1, but if we use the
 * DefaultRoleManager, it will return false.
 * GroupRoleManager is to handle this situation.
]]
GroupRoleManager = DefaultRoleManager:DefaultRoleManager()

--[[
     * GroupRoleManager is the constructor for creating an instance of the
     * GroupRoleManager implementation.
     *
     * @param maxHierarchyLevel the maximized allowed RBAC hierarchy level.
]]
function GroupRoleManager:new(maxHierarchyLevel)
    local o = DefaultRoleManager:DefaultRoleManager(maxHierarchyLevel, nil, nil)
    setmetatable(o, self)
    self.__index = self
    return o
end

--[[
     * hasLink determines whether role: name1 inherits role: name2.
     * domain is a prefix to the roles.
]]
function GroupRoleManager:hasLink(name1, name2, ...)

end


return GroupRoleManager