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

local Enforcer = require("src.main.Enforcer")
local path = os.getenv("PWD") or io.popen("cd"):read()
local BuiltInFunctions = require("src.util.BuiltInFunctions")

local function sort(t)
    table.sort(t, function (x, y)
        return x>y
    end)
    return t
end

describe("RBAC API tests", function ()
    it("Role API test", function ()
        local model  = path .. "/examples/rbac_model.conf"
        local policy  = path .. "/examples/rbac_policy.csv"

        local e = Enforcer:new(model, policy)

        assert.is.Same(e:GetRolesForUser("alice"), {"data2_admin"})
        assert.is.Same(e:GetRolesForUser("bob"), {})
        assert.is.Same(e:GetRolesForUser("data2_admin"), {})
        assert.is.Same(e:GetRolesForUser("non_existing_user"), {})

        assert.is.Same(e:GetUsersForRole("data2_admin"), {"alice"})
        assert.is.Same(e:GetUsersForRole("data1_admin"), {})

        assert.is.False(e:HasRoleForUser("alice", "data1_admin"))
        assert.is.True(e:HasRoleForUser("alice", "data2_admin"))

        e:AddRoleForUser("alice", "data1_admin")

        assert.is.Same(e:GetRolesForUser("alice"), {"data2_admin", "data1_admin"})
        assert.is.Same(e:GetRolesForUser("bob"), {})
        assert.is.Same(e:GetRolesForUser("data2_admin"), {})

        e:DeleteRoleForUser("alice", "data1_admin")

        assert.is.Same(e:GetRolesForUser("alice"), {"data2_admin"})
        assert.is.Same(e:GetRolesForUser("bob"), {})
        assert.is.Same(e:GetRolesForUser("data2_admin"), {})

        e:DeleteRolesForUser("alice")

        assert.is.Same(e:GetRolesForUser("alice"), {})
        assert.is.Same(e:GetRolesForUser("bob"), {})
        assert.is.Same(e:GetRolesForUser("data2_admin"), {})

        e:AddRoleForUser("alice", "data1_admin")
        e:DeleteUser("alice")

        assert.is.Same(e:GetRolesForUser("alice"), {})
        assert.is.Same(e:GetRolesForUser("bob"), {})
        assert.is.Same(e:GetRolesForUser("data2_admin"), {})

        e:AddRoleForUser("alice", "data2_admin")

        assert.is.False(e:enforce("alice", "data1", "read"))
	    assert.is.False(e:enforce("alice", "data1", "write"))
	    assert.is.True(e:enforce("alice", "data2", "read"))
        assert.is.True(e:enforce("alice", "data2", "write"))
        assert.is.False(e:enforce("bob", "data1", "read"))
        assert.is.False(e:enforce("bob", "data1", "write"))
        assert.is.False(e:enforce("bob", "data2", "read"))
        assert.is.True(e:enforce("bob", "data2", "write"))

        e:DeleteRole("data2_admin")

        assert.is.False(e:enforce("alice", "data1", "read"))
	    assert.is.False(e:enforce("alice", "data1", "write"))
	    assert.is.False(e:enforce("alice", "data2", "read"))
        assert.is.False(e:enforce("alice", "data2", "write"))
        assert.is.False(e:enforce("bob", "data1", "read"))
        assert.is.False(e:enforce("bob", "data1", "write"))
        assert.is.False(e:enforce("bob", "data2", "read"))
        assert.is.True(e:enforce("bob", "data2", "write"))
    end)

    it("Role API Domains test", function ()
        local model  = path .. "/examples/rbac_with_domains_model.conf"
        local policy  = path .. "/examples/rbac_with_domains_policy.csv"

        local e = Enforcer:new(model, policy)

        assert.is.True(e:HasRoleForUser("alice", "admin", "domain1"))
        assert.is.False(e:HasRoleForUser("alice", "admin", "domain2"))
        assert.is.Same(e:GetRolesForUser("alice", "domain1"), {"admin"})
        assert.is.Same(e:GetRolesForUser("bob", "domain1"), {})
        assert.is.Same(e:GetRolesForUser("admin", "domain1"), {})
        assert.is.Same(e:GetRolesForUser("non_exist", "domain1"), {})
        assert.is.Same(e:GetRolesForUser("alice", "domain2"), {})
        assert.is.Same(e:GetRolesForUser("bob", "domain2"), {"admin"})
        assert.is.Same(e:GetRolesForUser("admin", "domain2"), {})
        assert.is.Same(e:GetRolesForUser("non_exist", "domain2"), {})

        e:DeleteRoleForUser("alice", "admin", "domain1")
        e:AddRoleForUser("bob", "admin", "domain1")

        assert.is.Same(e:GetRolesForUser("alice", "domain1"), {})
        assert.is.Same(e:GetRolesForUser("bob", "domain1"), {"admin"})
        assert.is.Same(e:GetRolesForUser("admin", "domain1"), {})
        assert.is.Same(e:GetRolesForUser("non_exist", "domain1"), {})
        assert.is.Same(e:GetRolesForUser("alice", "domain2"), {})
        assert.is.Same(e:GetRolesForUser("bob", "domain2"), {"admin"})
        assert.is.Same(e:GetRolesForUser("admin", "domain2"), {})
        assert.is.Same(e:GetRolesForUser("non_exist", "domain2"), {})

        e:AddRoleForUser("alice", "admin", "domain1")
        e:DeleteRolesForUser("bob", "domain1")

        assert.is.Same(e:GetRolesForUser("alice", "domain1"), {"admin"})
        assert.is.Same(e:GetRolesForUser("bob", "domain1"), {})
        assert.is.Same(e:GetRolesForUser("admin", "domain1"), {})
        assert.is.Same(e:GetRolesForUser("non_exist", "domain1"), {})
        assert.is.Same(e:GetRolesForUser("alice", "domain2"), {})
        assert.is.Same(e:GetRolesForUser("bob", "domain2"), {"admin"})
        assert.is.Same(e:GetRolesForUser("admin", "domain2"), {})
        assert.is.Same(e:GetRolesForUser("non_exist", "domain2"), {})

        e:AddRolesForUser("bob", {"admin", "admin1", "admin2"}, "domain1")
        assert.is.Same(e:GetRolesForUser("bob", "domain1"), {"admin", "admin1", "admin2"})

        assert.is.Same(e:GetPermissionsForUser("admin", "domain1"), {{"admin", "domain1", "data1", "read"}, {"admin", "domain1", "data1", "write"}})
        assert.is.Same(e:GetPermissionsForUser("admin", "domain2"), {{"admin", "domain2", "data2", "read"}, {"admin", "domain2", "data2", "write"}})
    end)

    it("AddRoles test", function ()
        local model  = path .. "/examples/rbac_model.conf"
        local policy  = path .. "/examples/rbac_policy.csv"

        local e = Enforcer:new(model, policy)

        e:AddRolesForUser("alice", {"data1_admin", "data2_admin", "data3_admin"})
        -- The "alice" already has "data2_admin" , it will be return false. So "alice" just has "data2_admin".
        assert.is.Same(e:GetRolesForUser("alice"), {"data2_admin"})
        --delete role
        e:DeleteRoleForUser("alice", "data2_admin")

        e:AddRolesForUser("alice", {"data1_admin", "data2_admin", "data3_admin"})
        assert.is.Same(e:GetRolesForUser("alice"), {"data1_admin", "data2_admin", "data3_admin"})

        assert.is.True(e:enforce("alice", "data1", "read"))
        assert.is.True(e:enforce("alice", "data2", "read"))
        assert.is.True(e:enforce("alice", "data2", "write"))
    end)

    it("Permission API test", function ()
        local model  = path .. "/examples/basic_without_resources_model.conf"
        local policy  = path .. "/examples/basic_without_resources_policy.csv"

        local e = Enforcer:new(model, policy)

        assert.is.True(e:enforce("alice", "read"))
        assert.is.False(e:enforce("alice", "write"))
        assert.is.False(e:enforce("bob", "read"))
        assert.is.True(e:enforce( "bob", "write"))

        assert.is.Same(e:GetPermissionsForUser("alice"), {{"alice", "read"}})
        assert.is.Same(e:GetPermissionsForUser("bob"), {{"bob", "write"}})

        assert.is.True(e:HasPermissionForUser("alice", "read"))
        assert.is.False(e:HasPermissionForUser("alice", "write"))
        assert.is.False(e:HasPermissionForUser("bob", "read"))
        assert.is.True(e:HasPermissionForUser("bob", "write"))

        e:DeletePermission("read")

        assert.is.False(e:enforce("alice", "read"))
        assert.is.False(e:enforce("alice", "write"))
        assert.is.False(e:enforce("bob", "read"))
        assert.is.True(e:enforce( "bob", "write"))

        e:AddPermissionForUser("bob", "read")

        assert.is.False(e:enforce("alice", "read"))
        assert.is.False(e:enforce("alice", "write"))
        assert.is.True(e:enforce("bob", "read"))
        assert.is.True(e:enforce( "bob", "write"))

        e:DeletePermissionForUser("bob", "read")

        assert.is.False(e:enforce("alice", "read"))
        assert.is.False(e:enforce("alice", "write"))
        assert.is.False(e:enforce("bob", "read"))
        assert.is.True(e:enforce( "bob", "write"))

        e:DeletePermissionsForUser("bob")

        assert.is.False(e:enforce("alice", "read"))
        assert.is.False(e:enforce("alice", "write"))
        assert.is.False(e:enforce("bob", "read"))
        assert.is.False(e:enforce( "bob", "write"))
    end)

    it("Implicit Role API test", function ()
        local model  = path .. "/examples/rbac_model.conf"
        local policy  = path .. "/examples/rbac_with_hierarchy_policy.csv"

        local e = Enforcer:new(model, policy)

        assert.is.Same(e:GetPermissionsForUser("alice"), {{"alice", "data1", "read"}})
        assert.is.Same(e:GetPermissionsForUser("bob"), {{"bob", "data2", "write"}})

        assert.is.Same(e:GetImplicitRolesForUser("alice"), {"admin", "data1_admin", "data2_admin"})
        assert.is.Same(e:GetImplicitRolesForUser("bob"), {})

        model  = path .. "/examples/rbac_with_pattern_model.conf"
        policy  = path .. "/examples/rbac_with_pattern_policy.csv"

        e = Enforcer:new(model, policy)

        e:AddNamedMatchingFunc("g2", BuiltInFunctions.keyMatch)

        assert.is.Same(e:GetImplicitRolesForUser("cathy"), {"/book/1/2/3/4/5", "pen_admin"})
        assert.is.Same(e:GetRolesForUser("cathy"), {"/book/1/2/3/4/5", "pen_admin"})
    end)

    it("Implicit Permission API test", function ()
        local model  = path .. "/examples/rbac_model.conf"
        local policy  = path .. "/examples/rbac_with_hierarchy_policy.csv"

        local e = Enforcer:new(model, policy)

        assert.is.Same(e:GetPermissionsForUser("alice"), {{"alice", "data1", "read"}})
        assert.is.Same(e:GetPermissionsForUser("bob"), {{"bob", "data2", "write"}})

        assert.is.Same(e:GetImplicitPermissionsForUser("alice"), {{"alice", "data1", "read"}, {"data1_admin", "data1", "read"}, {"data1_admin", "data1", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}})
        assert.is.Same(e:GetImplicitPermissionsForUser("bob"), {{"bob", "data2", "write"}})
    end)

    it("Implicit Permission API with domain test", function ()
        local model  = path .. "/examples/rbac_with_domains_model.conf"
        local policy  = path .. "/examples/rbac_with_hierarchy_with_domains_policy.csv"

        local e = Enforcer:new(model, policy)

        assert.is.Same(e:GetImplicitPermissionsForUser("alice", "domain1"), {{"alice", "domain1", "data2", "read"}, {"role:reader", "domain1", "data1", "read"}, {"role:writer", "domain1", "data1", "write"}})
    end)

    it("Implicit Users API test", function ()
        local model  = path .. "/examples/rbac_model.conf"
        local policy  = path .. "/examples/rbac_with_hierarchy_policy.csv"

        local e = Enforcer:new(model, policy)

        assert.is.Same(e:GetImplicitUsersForPermission("data1", "read"), {"alice"})
        assert.is.Same(e:GetImplicitUsersForPermission("data1", "write"), {"alice"})
        assert.is.Same(e:GetImplicitUsersForPermission("data2", "read"), {"alice"})
        assert.is.Same(sort(e:GetImplicitUsersForPermission("data2", "write")), sort({"alice", "bob"}))

        e:clearPolicy()

        e:AddPolicy("admin", "data1", "read")
        e:AddPolicy("bob", "data1", "read")
        e:AddGroupingPolicy("alice", "admin")

        assert.is.Same(sort(e:GetImplicitUsersForPermission("data1", "read")), sort({"alice", "bob"}))
    end)

    it("Get Implicit Resources for User test", function ()
        local model  = path .. "/examples/rbac_with_pattern_model.conf"
        local policy  = path .. "/examples/rbac_with_pattern_policy.csv"

        local e = Enforcer:new(model, policy)

        local function sort2D(t)
            table.sort(t, function (x, y)
                return x[2]>y[2]
            end)
            return t
        end

        assert.is.Same(sort2D(e:GetImplicitResourcesForUser("alice")), sort2D({
            {"alice", "/pen/1", "GET"},
            {"alice", "/pen2/1", "GET"},
            {"alice", "/book/:id", "GET"},
            {"alice", "/book2/{id}", "GET"},
            {"alice", "/book/*", "GET"},
            {"alice", "book_group", "GET"}
        }))
        assert.is.Same(sort2D(e:GetImplicitResourcesForUser("bob")), sort2D({
            {"bob", "/pen2/{id}", "GET"},
		    {"bob", "/pen/:id", "GET"},
		    {"bob", "pen_group", "GET"}
        }))
        assert.is.Same(sort2D(e:GetImplicitResourcesForUser("cathy")), sort2D({
            {"cathy", "/pen2/{id}", "GET"},
            {"cathy", "/pen/:id", "GET"},
            {"cathy", "pen_group", "GET"}
        }))
    end)

    it("Get Implicit Users For Role", function ()
        local model  = path .. "/examples/rbac_with_pattern_model.conf"
        local policy  = path .. "/examples/rbac_with_pattern_policy.csv"

        local e = Enforcer:new(model, policy)

        assert.is.Same(sort(e:GetImplicitUsersForRole("book_admin")), sort({"alice"}))
        assert.is.Same(sort(e:GetImplicitUsersForRole("pen_admin")), sort({"cathy", "bob"}))
        assert.is.Same(sort(e:GetImplicitUsersForRole("book_group")), sort({"/book/:id", "/book2/{id}", "/book/*"}))
        assert.is.Same(sort(e:GetImplicitUsersForRole("pen_group")), sort({"/pen2/{id}", "/pen/:id"}))
    end)
end)

describe("RBAC API with domains tests", function ()
    it("Get Implicit Roles for Domain User test", function ()
        local model  = path .. "/examples/rbac_with_domains_model.conf"
        local policy  = path .. "/examples/rbac_with_hierarchy_with_domains_policy.csv"

        local e = Enforcer:new(model, policy)

        assert.is.Same(e:GetRolesForUserInDomain("alice", "domain1"), {"role:global_admin"})

        assert.is.Same(e:GetImplicitRolesForUser("alice", "domain1"), {"role:global_admin", "role:reader", "role:writer"})
    end)

    it("User API with Domains test", function ()
        local model  = path .. "/examples/rbac_with_domains_model.conf"
        local policy  = path .. "/examples/rbac_with_domains_policy.csv"

        local e = Enforcer:new(model, policy)

        assert.is.Same(e:GetUsersForRole("admin", "domain1"), {"alice"})
        assert.is.Same(e:GetUsersForRoleInDomain("admin", "domain1"), {"alice"})

        assert.is.Same(e:GetUsersForRole("non_exist", "domain1"), {})
        assert.is.Same(e:GetUsersForRoleInDomain("non_exist", "domain1"), {})

        assert.is.Same(e:GetUsersForRole("admin", "domain2"), {"bob"})
        assert.is.Same(e:GetUsersForRoleInDomain("admin", "domain2"), {"bob"})

        assert.is.Same(e:GetUsersForRole("non_exist", "domain2"), {})
        assert.is.Same(e:GetUsersForRoleInDomain("non_exist", "domain2"), {})

        e:DeleteRoleForUserInDomain("alice", "admin", "domain1")
        e:AddRoleForUserInDomain("bob", "admin", "domain1")

        assert.is.Same(e:GetUsersForRole("admin", "domain1"), {"bob"})
        assert.is.Same(e:GetUsersForRoleInDomain("admin", "domain1"), {"bob"})

        assert.is.Same(e:GetUsersForRole("non_exist", "domain1"), {})
        assert.is.Same(e:GetUsersForRoleInDomain("non_exist", "domain1"), {})

        assert.is.Same(e:GetUsersForRole("admin", "domain2"), {"bob"})
        assert.is.Same(e:GetUsersForRoleInDomain("admin", "domain2"), {"bob"})

        assert.is.Same(e:GetUsersForRole("non_exist", "domain2"), {})
        assert.is.Same(e:GetUsersForRoleInDomain("non_exist", "domain2"), {})

    end)

    it("Role API with Domains test", function ()
        local model  = path .. "/examples/rbac_with_domains_model.conf"
        local policy  = path .. "/examples/rbac_with_domains_policy.csv"

        local e = Enforcer:new(model, policy)

        assert.is.Same(e:GetRolesForUser("alice", "domain1"), {"admin"})
        assert.is.Same(e:GetRolesForUserInDomain("alice", "domain1"), {"admin"})

        assert.is.Same(e:GetRolesForUser("bob", "domain1"), {})
        assert.is.Same(e:GetRolesForUserInDomain("bob", "domain1"), {})

        assert.is.Same(e:GetRolesForUser("admin", "domain1"), {})
        assert.is.Same(e:GetRolesForUserInDomain("admin", "domain1"), {})

        assert.is.Same(e:GetRolesForUser("non_exist", "domain1"), {})
        assert.is.Same(e:GetRolesForUserInDomain("non_exist", "domain1"), {})

        assert.is.Same(e:GetRolesForUser("alice", "domain2"), {})
        assert.is.Same(e:GetRolesForUserInDomain("alice", "domain2"), {})

        assert.is.Same(e:GetRolesForUser("bob", "domain2"), {"admin"})
        assert.is.Same(e:GetRolesForUserInDomain("bob", "domain2"), {"admin"})

        assert.is.Same(e:GetRolesForUser("admin", "domain2"), {})
        assert.is.Same(e:GetRolesForUserInDomain("admin", "domain2"), {})

        assert.is.Same(e:GetRolesForUser("non_exist", "domain2"), {})
        assert.is.Same(e:GetRolesForUserInDomain("non_exist", "domain2"), {})

        e:DeleteRoleForUserInDomain("alice", "admin", "domain1")
        e:AddRoleForUserInDomain("bob", "admin", "domain1")

        assert.is.Same(e:GetRolesForUser("alice", "domain1"), {})
        assert.is.Same(e:GetRolesForUserInDomain("alice", "domain1"), {})

        assert.is.Same(e:GetRolesForUser("bob", "domain1"), {"admin"})
        assert.is.Same(e:GetRolesForUserInDomain("bob", "domain1"), {"admin"})

        assert.is.Same(e:GetRolesForUser("admin", "domain1"), {})
        assert.is.Same(e:GetRolesForUserInDomain("admin", "domain1"), {})

        assert.is.Same(e:GetRolesForUser("non_exist", "domain1"), {})
        assert.is.Same(e:GetRolesForUserInDomain("non_exist", "domain1"), {})

        assert.is.Same(e:GetRolesForUser("alice", "domain2"), {})
        assert.is.Same(e:GetRolesForUserInDomain("alice", "domain2"), {})

        assert.is.Same(e:GetRolesForUser("bob", "domain2"), {"admin"})
        assert.is.Same(e:GetRolesForUserInDomain("bob", "domain2"), {"admin"})

        assert.is.Same(e:GetRolesForUser("admin", "domain2"), {})
        assert.is.Same(e:GetRolesForUserInDomain("admin", "domain2"), {})

        assert.is.Same(e:GetRolesForUser("non_exist", "domain2"), {})
        assert.is.Same(e:GetRolesForUserInDomain("non_exist", "domain2"), {})

        e:AddRoleForUserInDomain("alice", "admin", "domain1")
        e:DeleteRolesForUser("bob", "domain1")

        assert.is.Same(e:GetRolesForUser("alice", "domain1"), {"admin"})
        assert.is.Same(e:GetRolesForUserInDomain("alice", "domain1"), {"admin"})

        assert.is.Same(e:GetRolesForUser("bob", "domain1"), {})
        assert.is.Same(e:GetRolesForUserInDomain("bob", "domain1"), {})

        assert.is.Same(e:GetRolesForUser("admin", "domain1"), {})
        assert.is.Same(e:GetRolesForUserInDomain("admin", "domain1"), {})

        assert.is.Same(e:GetRolesForUser("non_exist", "domain1"), {})
        assert.is.Same(e:GetRolesForUserInDomain("non_exist", "domain1"), {})

        assert.is.Same(e:GetRolesForUser("alice", "domain2"), {})
        assert.is.Same(e:GetRolesForUserInDomain("alice", "domain2"), {})

        assert.is.Same(e:GetRolesForUser("bob", "domain2"), {"admin"})
        assert.is.Same(e:GetRolesForUserInDomain("bob", "domain2"), {"admin"})

        assert.is.Same(e:GetRolesForUser("admin", "domain2"), {})
        assert.is.Same(e:GetRolesForUserInDomain("admin", "domain2"), {})

        assert.is.Same(e:GetRolesForUser("non_exist", "domain2"), {})
        assert.is.Same(e:GetRolesForUserInDomain("non_exist", "domain2"), {})
    end)

    it("Permission API in Domain test", function ()
        local model  = path .. "/examples/rbac_with_domains_model.conf"
        local policy  = path .. "/examples/rbac_with_domains_policy.csv"

        local e = Enforcer:new(model, policy)

        assert.is.Same(e:GetPermissionsForUserInDomain("alice", "domain1"), {})
        assert.is.Same(e:GetPermissionsForUserInDomain("bob", "domain1"), {})
        assert.is.Same(e:GetPermissionsForUserInDomain("admin", "domain1"), {{"admin", "domain1", "data1", "read"}, {"admin", "domain1", "data1", "write"}})
        assert.is.Same(e:GetPermissionsForUserInDomain("non_exist", "domain1"), {})

        assert.is.Same(e:GetPermissionsForUserInDomain("alice", "domain2"), {})
        assert.is.Same(e:GetPermissionsForUserInDomain("bob", "domain2"), {})
        assert.is.Same(e:GetPermissionsForUserInDomain("admin", "domain2"), {{"admin", "domain2", "data2", "read"}, {"admin", "domain2", "data2", "write"}})
        assert.is.Same(e:GetPermissionsForUserInDomain("non_exist", "domain2"), {})
    end)

    it("Get All Users by Domain test", function ()
        local model  = path .. "/examples/rbac_with_domains_model.conf"
        local policy  = path .. "/examples/rbac_with_domains_policy.csv"

        local e = Enforcer:new(model, policy)

        assert.is.Same(e:GetAllUsersByDomain("domain1"), {"alice", "admin"})
        assert.is.Same(e:GetAllUsersByDomain("domain2"), {"bob", "admin"})
    end)

    it("Delete All Users by Domain test", function ()
        local function testDeleteAllUsersByDomain(domain, expectedPolicy, expectedGroupingPolicy)
            local model  = path .. "/examples/rbac_with_domains_model.conf"
            local policy  = path .. "/examples/rbac_with_domains_policy.csv"

            local e = Enforcer:new(model, policy)

            e:DeleteAllUsersByDomain(domain)
            assert.is.Same(e:GetPolicy(), expectedPolicy)
            assert.is.Same(e:GetGroupingPolicy(), expectedGroupingPolicy)
        end

        testDeleteAllUsersByDomain("domain1", {
            {"admin", "domain2", "data2", "read"},
            {"admin", "domain2", "data2", "write"}
        }, {
            {"bob", "admin", "domain2"}
        })

        testDeleteAllUsersByDomain("domain2", {
            {"admin", "domain1", "data1", "read"},
            {"admin", "domain1", "data1", "write"}
        }, {
            {"alice", "admin", "domain1"}
        })
    end)

    it("Delete Domains test", function ()
        local function testDeleteDomains(expectedPolicy, ...)
            local model  = path .. "/examples/rbac_with_domains_model.conf"
            local policy  = path .. "/examples/rbac_with_domains_policy.csv"

            local e = Enforcer:new(model, policy)

            e:DeleteDomains(...)
            assert.is.Same(e:GetPolicy(), expectedPolicy)
        end

        testDeleteDomains({
            {"admin", "domain2", "data2", "read"},
            {"admin", "domain2", "data2", "write"}
        }, "domain1")

        testDeleteDomains({})
    end)
end)
