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

local role_manager_module = require("src.rbac.DefaultRoleManager")

-- test function for testing the matching function functionality in Role Manager
-- true if n1=n2 or n1 matches the pattern of n2 or n2 matches the pattern of n1
-- "?" character needed before any pattern
function testMatchingFunc(...)
    local args = {...}
    local n1 = args[1]
    local n2 = args[2]
    if n1 == n2 then
        return true
    elseif string.sub(n1, 1, 1) == "?" then
        if string.find(n2, string.sub(n1, 2)) then
            return true
        end
    elseif string.sub(n2, 1, 1) == "?" then
        if string.find(n1, string.sub(n2, 2)) then
            return true
        end
    end
    return false
end

describe("DefaultRoleManager tests", function ()
    it("test role", function ()
        local rm = DefaultRoleManager:new(10)
        rm:addLink("u1", "g1")
        rm:addLink("u2", "g1")
        rm:addLink("u3", "g2")
        rm:addLink("u4", "g2")
        rm:addLink("u4", "g3")
        rm:addLink("g1", "g3")
        --[[
        # Current role inheritance tree:
        #             g3    g2
        #            /  \  /  \
        #          g1    u4    u3
        #         /  \
        #       u1    u2
        ]]
        assert.is.True(rm:hasLink("u1", "g1"))
        assert.is.False(rm:hasLink("u1", "g2"))
        assert.is.True(rm:hasLink("u1", "g3"))
        assert.is.True(rm:hasLink("u2", "g1"))
        assert.is.False(rm:hasLink("u2", "g2"))
        assert.is.True(rm:hasLink("u2", "g3"))
        assert.is.False(rm:hasLink("u3", "g1"))
        assert.is.True(rm:hasLink("u3", "g2"))
        assert.is.False(rm:hasLink("u3", "g3"))
        assert.is.False(rm:hasLink("u4", "g1"))
        assert.is.True(rm:hasLink("u4", "g2"))
        assert.is.True(rm:hasLink("u4", "g3"))

        assert.are.same(rm:getRoles("u1"),{"g1"})
        assert.are.same(rm:getRoles("u2"),{"g1"})
        assert.are.same(rm:getRoles("u3"),{"g2"})
        assert.are.same(rm:getRoles("u4"),{"g2", "g3"})
        assert.are.same(rm:getRoles("g1"),{"g3"})
        assert.are.same(rm:getRoles("g2"),{})
        assert.are.same(rm:getRoles("g3"),{})

        assert.are.same(rm:getUsers("u1"),{})
        assert.are.same(rm:getUsers("u2"),{})
        assert.are.same(rm:getUsers("u3"),{})
        assert.are.same(rm:getUsers("u4"),{})
        assert.are.same(rm:getUsers("g1"),{"u2", "u1"})
        assert.are.same(rm:getUsers("g2"),{"u3", "u4"})
        assert.are.same(rm:getUsers("g3"),{"u4", "g1"})

        rm:deleteLink("g1", "g3")
        rm:deleteLink("u4", "g2")

        --[[
        # Current role inheritance tree after deleting the links:
        #             g3    g2
        #               \     \
        #          g1    u4    u3
        #         /  \
        #       u1    u2
        ]]

        assert.is.True(rm:hasLink("u1", "g1"))
        assert.is.False(rm:hasLink("u1", "g2"))
        assert.is.False(rm:hasLink("u1", "g3"))
        assert.is.True(rm:hasLink("u2", "g1"))
        assert.is.False(rm:hasLink("u2", "g2"))
        assert.is.False(rm:hasLink("u2", "g3"))
        assert.is.False(rm:hasLink("u3", "g1"))
        assert.is.True(rm:hasLink("u3", "g2"))
        assert.is.False(rm:hasLink("u3", "g3"))
        assert.is.False(rm:hasLink("u4", "g1"))
        assert.is.False(rm:hasLink("u4", "g2"))
        assert.is.True(rm:hasLink("u4", "g3"))

        assert.are.same(rm:getRoles("u1"),{"g1"})
        assert.are.same(rm:getRoles("u2"),{"g1"})
        assert.are.same(rm:getRoles("u3"),{"g2"})
        assert.are.same(rm:getRoles("u4"),{"g3"})
        assert.are.same(rm:getRoles("g1"),{})
        assert.are.same(rm:getRoles("g2"),{})
        assert.are.same(rm:getRoles("g3"),{})
    end)

    it("test domain role", function ()
        local rm = DefaultRoleManager:new(10)
        rm:addLink("u1", "g1", "domain1")
        rm:addLink("u2", "g1", "domain1")
        rm:addLink("u3", "admin", "domain2")
        rm:addLink("u4", "admin", "domain2")
        rm:addLink("u4", "admin", "domain1")
        rm:addLink("g1", "admin", "domain1")
        --[[
        # Current role inheritance tree:
        #       domain1:admin    domain2:admin
        #            /       \  /       \
        #      domain1:g1     u4         u3
        #         /  \
        #       u1    u2
        ]]
        assert.is.True(rm:hasLink("u1", "g1", "domain1"))
        assert.is.False(rm:hasLink("u1", "g1", "domain2"))
        assert.is.True(rm:hasLink("u1", "admin", "domain1"))
        assert.is.False(rm:hasLink("u1", "admin", "domain2"))

        assert.is.True(rm:hasLink("u2", "g1", "domain1"))
        assert.is.False(rm:hasLink("u2", "g1", "domain2"))
        assert.is.True(rm:hasLink("u2", "admin", "domain1"))
        assert.is.False(rm:hasLink("u2", "admin", "domain2"))

        assert.is.False(rm:hasLink("u3", "g1", "domain1"))
        assert.is.False(rm:hasLink("u3", "g1", "domain2"))
        assert.is.False(rm:hasLink("u3", "admin", "domain1"))
        assert.is.True(rm:hasLink("u3", "admin", "domain2"))

        assert.is.False(rm:hasLink("u4", "g1", "domain1"))
        assert.is.False(rm:hasLink("u4", "g1", "domain2"))
        assert.is.True(rm:hasLink("u4", "admin", "domain1"))
        assert.is.True(rm:hasLink("u4", "admin", "domain2"))
    end)

    it("test clear", function ()
        local rm = DefaultRoleManager:new(10)
        rm:addLink("u1", "g1")
        rm:addLink("u2", "g1")
        rm:addLink("u3", "g2")
        rm:addLink("u4", "g2")
        rm:addLink("u4", "g3")
        rm:addLink("g1", "g3")
        --[[
        # Current role inheritance tree:
        #             g3    g2
        #            /  \  /  \
        #          g1    u4    u3
        #         /  \
        #       u1    u2
        ]]
        rm:clear()
        
        -- All data is cleared.
        -- No role inheritance now.

        assert.is.False(rm:hasLink("u1", "g1"))
        assert.is.False(rm:hasLink("u1", "g2"))
        assert.is.False(rm:hasLink("u1", "g3"))
        assert.is.False(rm:hasLink("u2", "g1"))
        assert.is.False(rm:hasLink("u2", "g2"))
        assert.is.False(rm:hasLink("u2", "g3"))
        assert.is.False(rm:hasLink("u3", "g1"))
        assert.is.False(rm:hasLink("u3", "g2"))
        assert.is.False(rm:hasLink("u3", "g3"))
        assert.is.False(rm:hasLink("u4", "g1"))
        assert.is.False(rm:hasLink("u4", "g2"))
        assert.is.False(rm:hasLink("u4", "g3"))
    end)

    it("test matchingFunc", function ()
        local rm = DefaultRoleManager:new(10, testMatchingFunc)
        rm:addLink("u1", "g1")
        rm:addLink("u3", "g2")
        rm:addLink("u3", "g3")
        rm:addLink("?^[+-]?u%d+$", "g2")

        assert.is.True(rm:hasLink("u1", "g1"))
        assert.is.True(rm:hasLink("u1", "g2"))
        assert.is.False(rm:hasLink("u1", "g3"))

        assert.is.False(rm:hasLink("u2", "g1"))
        assert.is.True(rm:hasLink("u2", "g2"))
        assert.is.False(rm:hasLink("u2", "g3"))

        assert.is.False(rm:hasLink("u3", "g1"))
        assert.is.True(rm:hasLink("u3", "g2"))
        assert.is.True(rm:hasLink("u3", "g3"))
    end)

    it("test one to many", function ()
        local rm = DefaultRoleManager:new(10, testMatchingFunc)
        rm:addLink("u1", "?^[+-]?g%d+$")
        assert.is.True(rm:hasLink("u1", "g1"))
        assert.is.True(rm:hasLink("u1", "g2"))
        assert.is.False(rm:hasLink("u2", "g1"))
        assert.is.False(rm:hasLink("u2", "g2"))
    end)

    it("test many to one", function ()
        local rm = DefaultRoleManager:new(10, testMatchingFunc)
        rm:addLink("?^[+-]?u%d+$", "g1")
        assert.is.True(rm:hasLink("u1", "g1"))
        assert.is.True(rm:hasLink("u2", "g1"))
        assert.is.False(rm:hasLink("u1", "g2"))
        assert.is.False(rm:hasLink("u2", "g2"))
    end)

    it("test matching function order", function ()
        local rm = DefaultRoleManager:new(10, testMatchingFunc)

        rm:addLink("?^[+-]?g%d+$", "root")
        rm:addLink("u1", "g1")
        assert.is.True(rm:hasLink("u1", "root"))

        rm:clear()

        rm:addLink("u1", "g1")
        rm:addLink("?^[+-]?g%d+$", "root")
        assert.is.True(rm:hasLink("u1", "root"))

        rm:clear()

        rm:addLink("u1", "?^[+-]?g%d+$")
        rm:addLink("g1", "root")
        assert.is.True(rm:hasLink("u1", "root"))

        rm:clear()

        rm:addLink("g1", "root")
        rm:addLink("u1", "?^[+-]?g%d+$")
        assert.is.True(rm:hasLink("u1", "root"))
    end)

    it("test toString", function ()
        local rm = DefaultRoleManager:new(10)
        rm:addLink("u1", "g1")
        rm:addLink("u2", "g1")
        rm:addLink("u3", "g2")
        rm:addLink("u4", "g2")
        rm:addLink("u4", "g3")
        rm:addLink("g1", "g3")
        --[[
        # Current role inheritance tree:
        #             g3    g2
        #            /  \  /  \
        #          g1    u4    u3
        #         /  \
        #       u1    u2
        ]]

        assert.are.same(rm:createRole("u1"):toString(), "u1 < g1")
        assert.are.same(rm:createRole("g1"):toString(), "g1 < g3")
        assert.are.same(rm:createRole("u4"):toString(), "u4 < g2, g3")
    end)
end)
