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

require "src/rbac/RoleManager"
--[[
    * Assertion represents an expression in a section of the model.
    * For example: r = sub, obj, act
    policy = {{}}
]]
Assertion = {}

function Assertion:new()
    local o = {}
    o.key = ""
    o.value = ""
    o.tokens = {}
    o.policy = {}
    o.RM = {}
    o.policyMap={}
    setmetatable(o,self)
    self.__index = self
    return o
end

function Assertion:buildRoleLinks(rm)
    self.RM = rm
    local count = 0
    for i = 1, string.len(self.value) do
        if string.sub(self.value,i,i) == '_' then
            count = count + 1
        end
    end

    if count < 2 then
        error("the number of '_' in role definition should be at least 2")
    end

    for _, rule in pairs(self.policy) do

        if #rule < count then
            error("grouping policy elements do not meet role definition")
        end

        if rule[3] then
            self.RM:addLink(rule[1], rule[2], rule[3])
        else
            self.RM:addLink(rule[1], rule[2])
        end

    end

end

function Assertion:buildIncrementalRoleLinks(rm, op, rules)
    self.RM = rm
    local count = 0
    for i = 1, string.len(self.value) do
        if string.sub(self.value,i,i) == '_' then
            count = count + 1
        end
    end

    if count < 2 then
        error("the number of '_' in role definition should be at least 2")
    end

    for _, rule in pairs(rules) do

        if #rule < count then
            error("grouping policy elements do not meet role definition")
        end

        if op == "POLICY_ADD" then
            if rule[3] then
                self.RM:addLink(rule[1], rule[2], rule[3])
            else
                self.RM:addLink(rule[1], rule[2])
            end
        elseif op == "POLICY_REMOVE" then
            if rule[3] then
                self.RM:deleteLink(rule[1], rule[2], rule[3])
            else
                self.RM:deleteLink(rule[1], rule[2])
            end
        else
            error("invalid operation")
        end
    end
end
