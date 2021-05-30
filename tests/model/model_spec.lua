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

local model_module = require("src.model.Model")
local path = os.getenv("PWD") or io.popen("cd"):read()

local basic_path  = path .. "/examples/basic_model.conf"
local rbac_path = path .. "/examples/rbac_model.conf"
local rbac_with_domains_path = path .. "/examples/rbac_with_domains_model.conf"

describe("model tests", function() 
    
    it("test getPolicy", function ()
        local m = Model:new()
        m:loadModel(basic_path)

        local rule = {'admin', 'domain1', 'data1', 'read'}
        m:addPolicy("p", "p", rule)

        assert.are.same(m:getPolicy("p", "p"), {rule})
    end)
    
    it("test hasPolicy", function ()
        local m = Model:new()
        m:loadModel(basic_path)

        local rule = {'admin', 'domain1', 'data1', 'read'}
        m:addPolicy("p", "p", rule)

        assert.is.True(m:hasPolicy("p", "p", rule))
    end)

    it("test addPolicy", function ()
        local m = Model:new()
        m:loadModel(basic_path)

        local rule = {'admin', 'domain1', 'data1', 'read'}
        assert.is.False(m:hasPolicy("p", "p", rule))

        m:addPolicy("p", "p", rule)

        assert.is.True(m:hasPolicy("p", "p", rule))
    end)

    it("test removePolicy", function ()
        local m = Model:new()
        m:loadModel(basic_path)

        local rule = {'admin', 'domain1', 'data1', 'read'}
        assert.is.False(m:hasPolicy("p", "p", rule))

        m:addPolicy("p", "p", rule)
        assert.is.True(m:hasPolicy("p", "p", rule))

        m:removePolicy("p", "p", rule)
        assert.is.False(m:hasPolicy("p", "p", rule))
        assert.is.False(m:removePolicy("p", "p", rule))
    end)

    it("test addRolePolicy", function ()
        local m = Model:new()
        m:loadModel(rbac_path)

        local p_rule1 = {'alice', 'data1', 'read'}
        m:addPolicy("p", "p", p_rule1)
        assert.is.True(m:hasPolicy("p", "p", p_rule1))

        local p_rule2 = {'data2_admin', 'data2', 'read'}
        m:addPolicy("p", "p", p_rule2)
        assert.is.True(m:hasPolicy("p", "p", p_rule2))

        local g_rule = {'alice', 'data2_admin'}
        m:addPolicy("g", "g", g_rule)
        assert.is.True(m:hasPolicy("g", "g", g_rule))

        assert.are.same(m:getPolicy("p", "p"), {p_rule1, p_rule2})
        assert.are.same(m:getPolicy("g", "g"), {g_rule})
    end)

    it("test updatePolicy", function ()
        local m = Model:new()
        m:loadModel(basic_path)

        local oldRule = {'admin', 'domain1', 'data1', 'read'}
        local newRule = {'admin', 'domain1', 'data2', 'read'}

        m:addPolicy("p", "p", oldRule)
        assert.is.True(m:hasPolicy("p", "p", oldRule))

        m:updatePolicy("p", "p", oldRule, newRule)
        assert.is.False(m:hasPolicy("p", "p", oldRule))
        assert.is.True(m:hasPolicy("p", "p", newRule))
    end)

    it("test updatePolicies", function ()
        local m = Model:new()
        m:loadModel(basic_path)

        local oldRules = {
            {'admin', 'domain1', 'data1', 'read'},
            {'admin', 'domain1', 'data2', 'read'},
            {'admin', 'domain1', 'data3', 'read'}
        }
        local newRules = {
            {'admin', 'domain1', 'data4', 'read'},
            {'admin', 'domain1', 'data5', 'read'},
            {'admin', 'domain1', 'data6', 'read'}
        }

        m:addPolicies("p", "p", oldRules)

        for _, oldRule in pairs(oldRules) do
            assert.is.True(m:hasPolicy("p", "p", oldRule))
        end

        m:updatePolicies("p", "p", oldRules, newRules)

        for _, oldRule in pairs(oldRules) do
            assert.is.False(m:hasPolicy("p", "p", oldRule))
        end

        for _, newRule in pairs(newRules) do
            assert.is.True(m:hasPolicy("p", "p", newRule))
        end
    end)

    it("test clearPolicy", function ()
        local m = Model:new()
        m:loadModel(basic_path)

        local rule = {
            {'admin', 'domain1', 'data1', 'read'},
            {'admin', 'domain1', 'data2', 'read'}
        }
        m:addPolicies("p", "p", rule)
        assert.are.same(m:getPolicy("p", "p"), rule)

        m:clearPolicy()
        assert.are.same(m:getPolicy("p", "p"), {})
    end)

    it("test removeFilteredPolicy", function ()
        local m = Model:new()
        m:loadModel(rbac_with_domains_path)

        local rule = {'admin', 'domain1', 'data1', 'read'}
        m:addPolicy("p", "p", rule)

        local res = m:removeFilteredPolicy("p", "p", 1, "domain1", "data1")
        assert.is.True(res)

        local res = m:removeFilteredPolicy("p", "p", 1, "domain1", "data1")
        assert.is.False(res)
    end)

    it("test getFilteredPolicy", function ()
        local m = Model:new()
        m:loadModel(rbac_with_domains_path)

        local rules = {
            {'admin', 'domain1', 'data1', 'read'},
            {'admin', 'domain1', 'data2', 'read'},
            {'admin', 'domain2', 'data3', 'read'}
        }
        m:addPolicies("p", "p", rules)

        local res = m:getFilteredPolicy("p", "p", 1, "domain1")
        local filteredRules = {
            {'admin', 'domain1', 'data1', 'read'},
            {'admin', 'domain1', 'data2', 'read'}
        }
        assert.are.same(res, filteredRules)

    end)

    it("test printPolicy and printModel", function ()
        local m = Model:new()
        m:loadModel(basic_path)
        assert.has_no.errors(function ()
            m:printModel()
            m:printPolicy()
        end)
    end)
end)
