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

require "src/model/Assertion"
require "src/util/Util"
require "src/util/Log"

-- model's struct is map<string, map<string, Assertion>>
Policy = {}

function Policy:new()
    local o = {}
    o.logger = Log:getLogger()
    setmetatable(o, self)
    self.__index = self
    return o
end

--[[
     * buildRoleLinks initializes the roles in RBAC.
     *
     * @param rm the role manager.
]]
function Policy:buildRoleLinks(rm)
    if self.model["g"] then
        for _, v in pairs(self.model["g"]) do
            v:buildRoleLinks(rm)
        end
    end
end

--[[
     * printPolicy prints the policy to log.
]]
function Policy:printPolicy()
    self.logger:info("Policy: \n")
    if self.model["p"] then
        for k, ast in pairs(self.model["p"]) do
            self.logger:info("%s:   %s:", k, ast.value)
            self.logger:info(ast.policy)
        end
    end

    if self.model["g"] then
        for k, ast in pairs(self.model["g"]) do
            self.logger:info("%s:   %s:", k, ast.value)
            self.logger:info(ast.policy)
        end
    end
end

--[[
     * savePolicyToText saves the policy to the text.
     *
     * @return the policy text.
]]
function Policy:savePolicyToText()
    local res = ""

    if self.model["p"] then
        for key, ast in pairs(self.model["p"]) do
            for _, rule in pairs(ast.policy) do
                local x = string.format("%s, %s\n", key, table.concat(rule, ", "))
                res = res .. x
            end
        end
    end

    if self.model["g"] then
        for key, ast in pairs(self.model["g"]) do
            for _, rule in pairs(ast.policy) do
                local x = string.format("%s, %s\n", key, table.concat(rule, ", "))
                res = res .. x
            end
        end
    end

    return res
end

--[[
     * clearPolicy clears all current policy.
]]
function Policy:clearPolicy()
    if self.model["p"] then
        for _, v in pairs(self.model["p"]) do
            v.policy = {}
        end
    end

    if self.model["g"] then
        for _, v in pairs(self.model["g"]) do
            v.policy = {}
        end
    end
end

--[[
     * getPolicy gets all rules in a policy.
     *
     * @param sec the section, "p" or "g".
     * @param ptype the policy type, "p", "p2", .. or "g", "g2", ..
     * @return the policy rules of section sec and policy type ptype.
]]
function Policy:getPolicy(sec, ptype)
    return self.model[sec][ptype].policy
end

--[[
     * getFilteredPolicy gets rules based on field filters from a policy.
     *
     * @param sec the section, "p" or "g".
     * @param ptype the policy type, "p", "p2", .. or "g", "g2", ..
     * @param fieldIndex the policy rule's start index to be matched.
     * @param ... fieldValues the field values to be matched, value ""
     *                    means not to match this field.
     * @return the filtered policy rules of section sec and policy type ptype.
]]
function Policy:getFilteredPolicy(sec, ptype, fieldIndex, ...)
    local res = {}
    local fieldValues = {...}

    if not self.model[sec] then return res end
    if not self.model[sec][ptype] then return res end
    
    for _, rule in pairs(self.model[sec][ptype].policy) do
        local matched = true
        for i, v in ipairs(fieldValues) do
            if v ~= "" and rule[fieldIndex + i] ~= v then
                matched = false
                break
            end
        end
        if matched then
            table.insert(res, rule)
        end
    end

    return res
end

--[[
     * hasPolicy determines whether a model has the specified policy rule.
     *
     * @param sec the section, "p" or "g".
     * @param ptype the policy type, "p", "p2", .. or "g", "g2", ..
     * @param rule the policy rule.
     * @return whether the rule exists.
]]
function Policy:hasPolicy(sec, ptype, rule)
    for _, r in pairs(self.model[sec][ptype].policy) do
        if Util.arrayEquals(rule, r) then
            return true
        end
    end
    return false
end

--[[
     * addPolicy adds a policy rule to the model.
     *
     * @param sec the section, "p" or "g".
     * @param ptype the policy type, "p", "p2", .. or "g", "g2", ..
     * @param rule the policy rule.
     * @return succeeds or not.
]]
function Policy:addPolicy(sec, ptype, rule)
    if not self:hasPolicy(sec, ptype, rule) then
        table.insert(self.model[sec][ptype].policy, rule)
        return true
    end
    return false
end

--[[
     * addPolicies adds policy rules to the model.
     * @param sec the section, "p" or "g".
     * @param ptype the policy type, "p", "p2", .. or "g", "g2", ..
     * @param rules the policy rules.
     * @return succeeds or not.
]]
function Policy:addPolicies(sec, ptype, rules)
    local size = #self.model[sec][ptype].policy
    for _, rule in pairs(rules) do
        if not self:hasPolicy(sec, ptype, rule) then
            table.insert(self.model[sec][ptype].policy, rule)
        end
    end

    if size < #self.model[sec][ptype].policy then
        return true
    else 
        return false
    end
end

--[[
     * UpdatePolicy updates a policy rule from the model.
     *
     * @param sec the section, "p" or "g".
     * @param ptype the policy type, "p", "p2", .. or "g", "g2", ..
     * @param oldRule the old rule.
     * @param newRule the new rule.
     * @return succeeds or not.
]]
function Policy:updatePolicy(sec, ptype, oldRule, newRule)
    if not self:hasPolicy(sec, ptype, oldRule) then return false end

    for k, v in pairs(self.model[sec][ptype].policy) do
        if Util.arrayEquals(oldRule, v) then
            table.remove(self.model[sec][ptype].policy, k)
            table.insert(self.model[sec][ptype].policy, newRule)
        end
    end
end

-- Updates multiple policy rules from the model.
function Policy:updatePolicies(sec, ptype, oldRules, newRules)
    for _, rule in pairs(oldRules) do
        if not self:hasPolicy(sec, ptype, rule) then
            return false
        end
    end

    return self:removePolicies(sec, ptype, oldRules) and self:addPolicies(sec, ptype, newRules)
end

--[[
     * removePolicy removes a policy rule from the model.
     *
     * @param sec the section, "p" or "g".
     * @param ptype the policy type, "p", "p2", .. or "g", "g2", ..
     * @param rule the policy rule.
     * @return succeeds or not.
]]
function Policy:removePolicy(sec, ptype, rule)
    for i = 1, #self.model[sec][ptype].policy do
        local r = self.model[sec][ptype].policy[i]
        if Util.arrayEquals(r, rule) then
            table.remove(self.model[sec][ptype].policy, i)
            return true
        end
    end
    return false
end

--[[
     * removePolicies removes rules from the current policy.
     * @param sec the section, "p" or "g".
     * @param ptype the policy type, "p", "p2", .. or "g", "g2", ..
     * @param rules the policy rules.
     * @return succeeds or not.
]]
function Policy:removePolicies(sec, ptype, rules)
    local size = #self.model[sec][ptype].policy
    for _, rule in pairs(rules) do
        for k, v in pairs(self.model[sec][ptype].policy) do
            if Util.arrayEquals(rule, v) then
                table.remove(self.model[sec][ptype].policy, k)
                break
            end
        end
    end

    if size > #self.model[sec][ptype].policy then
        return true
    else 
        return false
    end
end

--[[
     * removeFilteredPolicyReturnsEffects removes policy rules based on field filters from the model.
     *
     * @param sec the section, "p" or "g".
     * @param ptype the policy type, "p", "p2", .. or "g", "g2", ..
     * @param fieldIndex the policy rule's start index to be matched.
     * @param ... fieldValues the field values to be matched, value ""
     *                    means not to match this field.
     * @return succeeds(effects.size() &gt; 0) or not.
]]
function Policy:removeFilteredPolicyReturnsEffects(sec, ptype, fieldIndex, ...)
    return {}
end

--[[
     * removeFilteredPolicy removes policy rules based on field filters from the model.
     *
     * @param sec the section, "p" or "g".
     * @param ptype the policy type, "p", "p2", .. or "g", "g2", ..
     * @param fieldIndex the policy rule's start index to be matched.
     * @param ... fieldValues the field values to be matched, value ""
     *                    means not to match this field.
     * @return succeeds or not.
]]
function Policy:removeFilteredPolicy(sec, ptype, fieldIndex, ...)
    local tmp = {}
    local res = false
    local fieldValues = {...}

    if not self.model[sec] then return res end
    if not self.model[sec][ptype] then return res end

    for _, rule in pairs(self.model[sec][ptype].policy) do
        local matched = true
        for i, value in pairs(fieldValues) do
            if value ~= "" and rule[fieldIndex+i] ~= value then
                matched = false
                break
            end
        end

        if matched then
            res = true
        else
            table.insert(tmp, rule)
        end
    end

    self.model[sec][ptype].policy = tmp
    return res
end

--[[
     * getValuesForFieldInPolicy gets all values for a field for all rules in a policy, duplicated values are removed.
     *
     * @param sec the section, "p" or "g".
     * @param ptype the policy type, "p", "p2", .. or "g", "g2", ..
     * @param fieldIndex the policy rule's index.
     * @return the field values specified by fieldIndex.
]]
function Policy:getValuesForFieldInPolicy(sec, ptype, fieldIndex)
    local values = {}

    for _, rule in pairs(self.model[sec][ptype].policy) do
        values[#values + 1] = rule[fieldIndex]
    end

    values = Util.arrayRemoveDuplications(values)
    return values
end

function Policy:buildIncrementalRoleLinks(rm, op, sec, ptype, rules)
    if sec == "g" then
        self.model[sec][ptype]:buildIncrementalRoleLinks(rm, op, rules)
    end
end

function Policy:hasPolicies(sec, ptype, rules)
    for _, rule in pairs(rules) do
        if self:hasPolicy(sec, ptype, rule) then
            return true
        end
    end
    return false
end

return Policy
