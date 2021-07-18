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

local Util = require("src/util/Util")
local Log = require("src/util/Log")

-- model's struct is map<string, map<string, Assertion>>
local Policy = {}

function Policy:new()
    local o = {}
    o.logger = Log.getLogger()
    setmetatable(o, self)
    self.__index = self
    return o
end

--[[
     * buildRoleLinks initializes the roles in RBAC.
     *
     * @param rm the role manager.
]]
function Policy:buildRoleLinks(rmMap)
    if self.model["g"] then
        for ptype, ast in pairs(self.model["g"]) do
            local rm = rmMap[ptype]
            ast:buildRoleLinks(rm)
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
    local policy = Util.tableDeepCopy(self.model[sec][ptype].policy)
    return policy
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
    if type(fieldValues[1]) == "table" then
        fieldValues = fieldValues[1]
    end

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
    if self.model[sec][ptype].policyMap[table.concat(rule,",")]~=nil then
        return false
    else
        return true
    end
end

--[[
     * hasPolicies determines whether a model has any of the specified policies.
     *
     * @param sec the section, "p" or "g".
     * @param ptype the policy type, "p", "p2", .. or "g", "g2", ..
     * @param rules the policies rules.
     * @return whether one is found.
]]
function Policy:hasPolicies(sec, ptype, rules)
    for i = 1, #rules do
        if self:hasPolicy(sec, ptype, rules[i]) then
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
    local assertion=self.model[sec][ptype]
    assertion.policy=table.insert(assertion.policy,rule)

    if  sec=="p" and assertion.priorityIndex>=0 then
        local idxInsert = tonumber(rule[assertion.priorityIndex])
        if idxInsert ~= nil then
            local i = #assertion.Policy - 1
            for  j=i,0,-1 do
                local idx= tonumber(assertion.policy[j-1][assertion.priorityIndex])
                if idx == nil then
                    break
                end
                if idx > idxInsert then
                    assertion.policy[j] = assertion.policy[j-1]
                else
                    break
                end
                i=i-1
            end
            assertion.policy[i] = rule
            assertion.policyMap[table.concat(rule,",")] = i
        end
    end
    assertion.policyMap[table.concat(rule,",")]=#self.model[sec][ptype].policy - 1
end

--[[
     * addPolicies adds policy rules to the model.
     * @param sec the section, "p" or "g".
     * @param ptype the policy type, "p", "p2", .. or "g", "g2", ..
     * @param rules the policy rules.
     * @return succeeds or not.
]]
function Policy:addPolicies(sec, ptype, rules)
    self.model.addPoliciesWithAffected(sec, ptype, rules)
end

--[[
     * addPoliciesWithAffected adds policy rules to the model.
     * @param sec the section, "p" or "g".
     * @param ptype the policy type, "p", "p2", .. or "g", "g2", ..
     * @param rules the policy rules.
     * @return succeeds or not.
]]
function Policy:addPoliciesWithAffected(sec, ptype, rules)
    local effected={}
    for _, rule in pairs(rules) do
        while true do
            local hashKey = table.concat(rule,",")
            if self.model[sec][ptype].policyMap[hashKey] then
                break
            end
            effected = table.insert(effected, rule)
            self.model.addPolicy(sec, ptype, rule)
        end
    end
    return effected
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
    local oldPolicy =table.concat(oldRule,",")
    local index=self.model[sec][ptype].policyMap[oldPolicy]
    if index==nil then
        return false
    end
    self.model[sec][ptype].policy[index]=newRule
    table.remove(self.model[sec][ptype].policyMap,oldPolicy)
    self.model[sec][ptype].policyMap[table.concat(newRule,",")]=index
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
    local index=self.model[sec][ptype].policyMap[table.concat(rule,",")]
    if index==nil then
        return false
    end
    self.model[sec][ptype].policy=table.remove(self.model[sec][ptype].policy,index)
    for i=index,#self.model[sec][ptype].policy do
        self.model[sec][ptype].policyMap[table.concat(self.model[sec][ptype].policy[i],",")]=i
    end
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
     * removePoliciesWithEffected removes policy rules based on field filters from the model.
     *
     * @param sec the section, "p" or "g".
     * @param ptype the policy type, "p", "p2", .. or "g", "g2", ..
     * @param rules the policy rules.
     * @return succeeds(effects.size() &gt; 0) or not.
]]
function Policy:removePoliciesWithEffected(sec, ptype, rules)
    local effected={}
    for  _,rule in pairs(rules) do
        while true do
            local index =self.model[sec][ptype].policyMap[table.concat(rule,",")]
            if index==nil then
                break
            end
            effected=table.insert(effected,rule)
            self.model[sec][ptype].policy=table.remove(self.model[sec][ptype].policy,index)
            table.remove(self.model[sec][ptype].policyMap,table.concat(rule,","))
            for i = index, #self.model[sec][ptype].Policy do
                self.model[sec][ptype].policyMap[table.concat(self.model[sec][ptype].policy[i], ",")] = i
            end
        end
    end
    return effected
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
function Policy:removeFilteredPolicy(sec, ptype, fieldIndex, fieldValues)
    local tmp = {}
    local res = false
    local effects = {}
    local firstIndex=-1
    if not self.model[sec] then return res end
    if not self.model[sec][ptype] then return res end

    for index, rule in pairs(self.model[sec][ptype].policy) do
        local matched = true
        for i, value in pairs(fieldValues) do
            if value ~= "" and rule[fieldIndex+i] ~= value then
                matched = false
                break
            end
        end

        if matched then
            if firstIndex==-1 then
                firstIndex=index
            end
            table.insert(effects, rule)
            table.remove(self.model[sec][ptype].policyMap,table.concat(rule,","))
            res = true
        else
            table.insert(tmp, rule)
        end
    end
    if firstIndex~=-1 then
        self.model[sec][ptype].policy = tmp
        for i=firstIndex,#self.model[sec][ptype].policy do
            self.model[sec][ptype].policyMap[table.concat(self.model[sec][ptype].policy[i],",")]=i
        end
    end
    return res, effects
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

function Policy:getValuesForFieldInPolicyAllTypes(sec, fieldIndex)
    local values = {}

    for ptype, _ in pairs(self.model[sec]) do
        local tvalues = self:getValuesForFieldInPolicy(sec, ptype, fieldIndex)
        for _, v in pairs(tvalues) do
            table.insert(values, v)
        end
    end

    return values
end

function Policy:buildIncrementalRoleLinks(rm, op, sec, ptype, rules)
    if sec == "g" then
        self.model[sec][ptype]:buildIncrementalRoleLinks(rm, op, rules)
    end
end

return Policy
