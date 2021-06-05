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

require "src/main/CoreEnforcer"
require "src/model/Model"
require "src/persist/BatchAdapter"
require "src/persist/FilteredAdapter"
require "src/util/Util"

-- InternalEnforcer = CoreEnforcer + Internal API.
InternalEnforcer = {}
setmetatable(InternalEnforcer, CoreEnforcer)
InternalEnforcer.__index = InternalEnforcer

--[[
    * addPolicy adds a rule to the current policy.
]]
function InternalEnforcer:addPolicy(sec, ptype, rule)
    if self.model:hasPolicy(sec, ptype, rule) then
        return false
    end

    if self.adapter and self.autoSave then

        local status, err = pcall(function () self.adapter:addPolicy(sec, ptype, rule) end)
        if status == false and string.sub(err, -15) == "not implemented" then
            -- log, continue
        elseif status == false then
            return false
        end
    end

    self.model:addPolicy(sec, ptype, rule)

    if sec == "g" then
        local rules = {}
        table.insert(rules, rule)
        self:buildIncrementalRoleLinks(self.model.PolicyOperations.POLICY_ADD, ptype, rules)
    end

    return true
    --TODO: update watcher, add logger
end

--[[
    * addPolicies adds rules to the current policy.
]]
function InternalEnforcer:addPolicies(sec, ptype, rules)
    if self.model:hasPolicies(sec, ptype, rules) then
        return false
    end

    if self.adapter and self.autoSave then

        local status, err = pcall(function () 
            if Util.isInstance(self.adapter, BatchAdapter) then
                self.adapter:addPolicies(sec, ptype, rules)
            end
        end)
        if status == false and string.sub(err, -15) == "not implemented" then
            -- log, continue
        elseif status == false then
            return false
        end
    end

    self.model:addPolicies(sec, ptype, rules)

    if sec == "g" then
        self:buildIncrementalRoleLinks(self.model.PolicyOperations.POLICY_ADD, ptype, rules)
    end

    return true
    --TODO: update watcher, add logger
end

--[[
    * buildIncrementalRoleLinks provides incremental build the role inheritance relations.
    * @param op Policy operations.
    * @param ptype policy type.
    * @param rules the rules.
]]
function InternalEnforcer:buildIncrementalRoleLinks(op, ptype, rules)
    self.model:buildIncrementalRoleLinks(self.rmMap[ptype], op, "g", ptype, rules)
end

--[[
    * removePolicy removes a rule from the current policy.
]]
function InternalEnforcer:removePolicy(sec, ptype, rule)
    if self.adapter and self.autoSave then

        local status, err = pcall(function () self.adapter:removePolicy(sec, ptype, rule) end)
        if status == false and string.sub(err, -15) == "not implemented" then
            -- log, continue
        elseif status == false then
            return false
        end
    end
    
    local ruleRemoved = self.model:removePolicy(sec, ptype, rule)

    if not ruleRemoved then
        return false
    end

    if sec == "g" then
        local rules = {}
        table.insert(rules, rule)
        self:buildIncrementalRoleLinks(self.model.PolicyOperations.POLICY_REMOVE, ptype, rules)
    end

    return true
    -- TODO: update watcher, add logger
end

--[[
    * updatePolicy updates an authorization rule from the current policy.
    * @param sec     the section, "p" or "g".
    * @param ptype   the policy type, "p", "p2", .. or "g", "g2", ..
    * @param oldRule the old rule.
    * @param newRule the new rule.
    * @return succeeds or not.
]]
function InternalEnforcer:updatePolicy(sec, ptype, oldRule, newRule)
    -- TODO: update dispatcher
    
    if self.adapter and self.autoSave then

        local status, err = pcall(function () self.adapter:updatePolicy(sec, ptype, oldRule, newRule) end)
        if status == false and string.sub(err, -15) == "not implemented" then
            -- log, continue
        elseif status == false then
            return false
        end
    end

    local ruleUpdated = self.model:updatePolicy(sec, ptype, oldRule, newRule)
    
    if not ruleUpdated then
        return false
    end

    if sec == "g" then
        local status, err = pcall(function () 
            local oldRules = {}
            table.insert(oldRules, oldRule)
            self:buildIncrementalRoleLinks(self.model.PolicyOperations.POLICY_REMOVE, ptype, oldRules)
        end)
        if status == false and string.sub(err, -15) == "not implemented" then
            -- log, continue
        elseif status == false then
            return false
        end
        
        status, err = pcall(function () 
            local newRules = {}
            table.insert(newRules, newRule)
            self:buildIncrementalRoleLinks(self.model.PolicyOperations.POLICY_ADD, ptype, newRules)
        end)
        if status == false and string.sub(err, -15) == "not implemented" then
            -- log, continue
        elseif status == false then
            return false
        end
    end

    return true
    -- TODO: update watcher, add logger
end

--[[
    * removePolicies removes rules from the current policy.
]]
function InternalEnforcer:removePolicies(sec, ptype, rules)
    if not self.model:hasPolicies(sec, ptype, rules) then
        return false
    end

    if self.adapter and self.autoSave then

        local status, err = pcall(function () 
            if Util.isInstance(self.adapter, BatchAdapter) then
                self.adapter:removePolicies(sec, ptype, rules)
            end
        end)
        if status == false and string.sub(err, -15) == "not implemented" then
            -- log, continue
        elseif status == false then
            return false
        end
    end

    local rulesRemoved = self.model:removePolicies(sec, ptype, rules)

    if not rulesRemoved then
        return false
    end

    if sec == "g" then
        self:buildIncrementalRoleLinks(self.model.PolicyOperations.POLICY_REMOVE, ptype, rules)
    end

    return true
    -- TODO: update watcher, add logger
end

--[[
    * removeFilteredPolicy removes rules based on field filters from the current policy.
]]
function InternalEnforcer:removeFilteredPolicy(sec, ptype, fieldIndex, fieldValues)
    if fieldValues == nil or #fieldValues == 0 then
        return false
    end

    if self.adapter and self.autoSave then
        
        local status, err = pcall(function () self.adapter:removeFilteredPolicy(sec, ptype, fieldIndex, fieldValues) end)
        if status == false and string.sub(err, -15) == "not implemented" then
            -- log, continue
        elseif status == false then
            return false
        end
    end

    local isRuleRemoved, effects = self.model:removeFilteredPolicy(sec, ptype, fieldIndex, fieldValues)

    if not isRuleRemoved then
        return false
    end

    if sec == "g" then
        self:buildIncrementalRoleLinks(self.model.PolicyOperations.POLICY_REMOVE, ptype, effects)
    end

    return true
    -- TODO: update watcher, add logger
end

return InternalEnforcer