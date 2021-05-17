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

local enforcer_module = require("src.main.Enforcer")
local path = os.getenv("PWD") or io.popen("cd"):read()

describe("Enforcer tests", function ()
    it("basic test", function ()
        local model  = path .. "/examples/basic_model.conf"
        local policy  = path .. "/examples/basic_policy.csv"

        local e = Enforcer:new(model, policy)
        assert.is.True(e:enforce("alice", "data1", "read"))
        assert.is.False(e:enforce("alice", "data2", "read"))
    end)

    it("rbac test", function ()
        local model  = path .. "/examples/rbac_model.conf"
        local policy  = path .. "/examples/rbac_policy.csv"

        local e = Enforcer:new(model, policy)
        assert.is.True(e:enforce("alice", "data1", "read"))
        assert.is.True(e:enforce("alice", "data2", "read"))
        assert.is.True(e:enforce("alice", "data2", "write"))
        assert.is.False(e:enforce("bob", "data1", "read"))
        assert.is.True(e:enforce("bob", "data2", "write"))
        assert.is.False(e:enforce("bogus", "data2", "write")) -- Non-existent subject
    end)

    it("keyMatch test", function ()
        local model  = path .. "/examples/keymatch_model.conf"
        local policy  = path .. "/examples/keymatch_policy.csv"

        local e = Enforcer:new(model, policy)
        assert.is.True(e:enforce("cathy", "/cathy_data", "GET"))
    end)

    it("abac sub_rule test", function ()
        local model  = path .. "/examples/abac_rule_model.conf"
        local policy  = path .. "/examples/abac_rule_policy.csv"
        local sub1 = {
            Name = "Alice",
            Age = 16
        }
        local sub2 = {
            Name = "Bob",
            Age = 20
        }
        local sub3 = {
            Name = "Alice",
            Age = 65
        }
        local e = Enforcer:new(model, policy)
        assert.is.False(e:enforce(sub1, "/data1", "read"))
        assert.is.False(e:enforce(sub1, "/data2", "read"))
        assert.is.False(e:enforce(sub1, "/data1", "write"))
        assert.is.True(e:enforce(sub1, "/data2", "write"))

        assert.is.True(e:enforce(sub2, "/data1", "read"))
        assert.is.False(e:enforce(sub2, "/data2", "read"))
        assert.is.False(e:enforce(sub2, "/data1", "write"))
        assert.is.True(e:enforce(sub2, "/data2", "write"))

        assert.is.False(e:enforce(sub3, "/data1", "write"))
        assert.is.True(e:enforce(sub3, "/data1", "read"))
        assert.is.False(e:enforce(sub3, "/data2", "read"))
        assert.is.True(e:enforce(sub1, "/data2", "write"))
    end)

    it("in of matcher test", function ()
        local model  = path .. "/examples/in_matcher_model.conf"
        local policy  = path .. "/examples/in_matcher_policy.csv"

        local e = Enforcer:new(model, policy)
        assert.is.True(e:enforce("alice", "data1", "read"))
        assert.is.True(e:enforce("alice", "data1", "write"))
        assert.is.False(e:enforce("alice", "data2", "read"))
        assert.is.False(e:enforce("alice", "data2", "write"))

        assert.is.False(e:enforce("bob", "data1", "read"))
        assert.is.False(e:enforce("bob", "data1", "write"))
        assert.is.True(e:enforce("bob", "data2", "read"))
        assert.is.True(e:enforce("bob", "data2", "write"))
    end)
end)
