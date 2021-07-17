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
local Util = require("src.util.Util")
local path = os.getenv("PWD") or io.popen("cd"):read()

describe("Management API tests", function ()
    it("Get Subjects, Objects, Actions, Roles test", function ()
        local model  = path .. "/examples/rbac_model.conf"
        local policy  = path .. "/examples/rbac_policy.csv"

        local e = Enforcer:new(model, policy)

        assert.is.Same(e:GetAllSubjects(), {"alice", "bob", "data2_admin"})
        assert.is.Same(e:GetAllObjects(), {"data1", "data2"})
        assert.is.Same(e:GetAllActions(), {"read", "write"})
        assert.is.Same(e:GetAllRoles(), {"data2_admin"})

        assert.is.Same(e:GetAllNamedSubjects("p"), {"alice", "bob", "data2_admin"})
        assert.is.Same(e:GetAllNamedObjects("p"), {"data1", "data2"})
        assert.is.Same(e:GetAllNamedActions("p"), {"read", "write"})
        assert.is.Same(e:GetAllNamedRoles("g"), {"data2_admin"})
    end)

    it("Get Policy test", function ()
        local model  = path .. "/examples/rbac_model.conf"
        local policy  = path .. "/examples/rbac_policy.csv"

        local e = Enforcer:new(model, policy)
        local res = {
            {"alice", "data1", "read"},
            {"bob", "data2", "write"},
            {"data2_admin", "data2", "read"},
            {"data2_admin", "data2", "write"}
        }
        assert.is.True(Util.array2DEquals(e:GetPolicy(), res))
    end)

    it("Get Filtered Policy test", function ()
        local model  = path .. "/examples/rbac_model.conf"
        local policy  = path .. "/examples/rbac_policy.csv"

        local e = Enforcer:new(model, policy)

        local res = {
            {"bob", "data2", "write"}
        }
        assert.is.Same(e:GetFilteredPolicy(0, "bob"), res)

        res = {
            {"bob", "data2", "write"},
            {"data2_admin", "data2", "read"},
            {"data2_admin", "data2", "write"}
        }

        assert.is.Same(e:GetFilteredPolicy(1, "data2"), res)
    end)

    it("Get Grouping Policy test", function ()
        local model  = path .. "/examples/rbac_model.conf"
        local policy  = path .. "/examples/rbac_policy.csv"

        local e = Enforcer:new(model, policy)

        local res = {
            {"alice", "data2_admin"}
        }

        assert.is.Same(e:GetGroupingPolicy(), res)
    end)

    it("Get Filtered Grouping Policy test", function ()
        local model  = path .. "/examples/rbac_model.conf"
        local policy  = path .. "/examples/rbac_policy.csv"

        local e = Enforcer:new(model, policy)

        local res = {
            {"alice", "data2_admin"}
        }

        assert.is.Same(e:GetFilteredGroupingPolicy(0, "alice"), res)
    end)

    it("Has Policy test", function ()
        local model  = path .. "/examples/rbac_model.conf"
        local policy  = path .. "/examples/rbac_policy.csv"

        local e = Enforcer:new(model, policy)

        assert.is.True(e:HasPolicy("alice", "data1", "read"))
        assert.is.False(e:HasPolicy("bob", "data2", "read"))
        assert.is.True(e:HasPolicy("bob", "data2", "write"))
    end)

    it("Has Grouping Policy test", function ()
        local model  = path .. "/examples/rbac_model.conf"
        local policy  = path .. "/examples/rbac_policy.csv"

        local e = Enforcer:new(model, policy)

        assert.is.True(e:HasGroupingPolicy("alice", "data2_admin"))
        assert.is.False(e:HasGroupingPolicy("bob", "data2_admin"))
    end)

    it("Modify Policy test", function ()
        local model  = path .. "/examples/rbac_model.conf"
        local policy  = path .. "/examples/rbac_policy.csv"

        local e = Enforcer:new(model, policy)

        local res = {
            {"alice", "data1", "read"},
		    {"bob", "data2", "write"},
		    {"data2_admin", "data2", "read"},
		    {"data2_admin", "data2", "write"}
        }

        assert.is.Same(e:GetPolicy(), res)

        e:RemovePolicy("alice", "data1", "read")
	    e:RemovePolicy("bob", "data2", "write")
	    e:RemovePolicy("alice", "data1", "read")
	    e:AddPolicy("eve", "data3", "read")
	    e:AddPolicy("eve", "data3", "read")

        local rules = {
            {"jack", "data4", "read"},
            {"jack", "data4", "read"},
            {"jack", "data4", "read"},
            {"katy", "data4", "write"},
            {"leyo", "data4", "read"},
            {"katy", "data4", "write"},
            {"katy", "data4", "write"},
            {"ham", "data4", "write"}
        }

        e:AddPolicies(rules)
        e:AddPolicies(rules)

        res = {
            {"data2_admin", "data2", "read"},
            {"data2_admin", "data2", "write"},
            {"eve", "data3", "read"},
            {"jack", "data4", "read"},
            {"katy", "data4", "write"},
            {"leyo", "data4", "read"},
            {"ham", "data4", "write"}
        }

        assert.is.Same(e:GetPolicy(), res)

        e:RemovePolicies(rules)
        e:RemovePolicies(rules)

        local namedPolicy = {"eve", "data3", "read"}
        e:RemoveNamedPolicy("p", namedPolicy)
        e:AddNamedPolicy("p", namedPolicy)

        res = {
            {"data2_admin", "data2", "read"},
            {"data2_admin", "data2", "write"},
            {"eve", "data3", "read"}
        }

        assert.is.Same(e:GetPolicy(), res)

        e:RemoveFilteredPolicy(1, "data2")
        assert.is.Same(e:GetPolicy(), {{"eve", "data3", "read"}})

        e:UpdatePolicy({"eve", "data3", "read"}, {"eve", "data3", "write"})
        assert.is.Same(e:GetPolicy(), {{"eve", "data3", "write"}})

        e:AddPolicies(rules)
        e:RemovePolicies({{"eve", "data3", "write"}, {"leyo", "data4", "read"}, {"katy", "data4", "write"}})
        e:AddPolicies({{"eve", "data3", "read"}, {"leyo", "data4", "write"}, {"katy", "data1", "write"}})

        assert.is.True(e:HasPolicy("eve", "data3", "read"))
        assert.is.True(e:HasPolicy("jack", "data4", "read"))
        assert.is.True(e:HasPolicy("katy", "data1", "write"))
        assert.is.True(e:HasPolicy("leyo", "data4", "write"))
        assert.is.True(e:HasPolicy("ham", "data4", "write"))
    end)

    it("Modify Grouping Policy test", function ()
        local model  = path .. "/examples/rbac_model.conf"
        local policy  = path .. "/examples/rbac_policy.csv"

        local e = Enforcer:new(model, policy)

        assert.is.True(e:HasGroupingPolicy("alice", "data2_admin"))

        local res = {
            {"alice", "data2_admin"}
        }
        assert.is.Same(e:GetGroupingPolicy(), res)

        e:AddGroupingPolicy("bob", "data2_admin")
        res = {
            {"alice", "data2_admin"},
            {"bob", "data2_admin"}
        }
        assert.is.Same(e:GetGroupingPolicy(), res)

        e:RemoveGroupingPolicy("bob", "data2_admin")

        local rules = {
            {"cathy", "data2_admin"},
            {"eve", "data2_admin"}
        }

        e:AddGroupingPolicies(rules)

        res = {
            {"alice", "data2_admin"},
            {"cathy", "data2_admin"},
            {"eve", "data2_admin"}
        }
        assert.is.Same(e:GetGroupingPolicy(), res)

        e:RemoveGroupingPolicies(rules)
        assert.is.Same(e:GetGroupingPolicy(), {{"alice", "data2_admin"}})

        e:UpdateGroupingPolicy({"alice", "data2_admin"}, {"bob", "data2_admin"})
        assert.is.Same(e:GetGroupingPolicy(), {{"bob", "data2_admin"}})

        e:UpdateGroupingPolicy({"bob", "data2_admin"}, {"alice", "data2_admin"})

        rules = {
            {"alice", "data1_admin"},
            {"bob", "data1_admin"},
            {"eve", "data2_admin"}
        }

        e:AddGroupingPolicies(rules)

        res = {
            {"alice", "data1_admin"},
            {"bob", "data1_admin"},
        }
        assert.is.Same(e:GetFilteredGroupingPolicy(1, "data1_admin"), res)
        
        e:RemoveFilteredGroupingPolicy(1, "data1_admin")

        res = {
            {"alice", "data2_admin"},
            {"eve", "data2_admin"}
        }
        assert.is.Same(e:GetGroupingPolicy(), res)
    end)
end)