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

require "src/config/Config"
require "src/model/Policy"
require "src/model/Assertion"
require "src/util/Util"

Model = Policy:new()

function Model:new()
    local o = {}
    setmetatable(o, self)
    self.__index = self
    self.model = {}
    self.sectionNameMap = {
         ["r"] = "request_definition",
         ["p"] = "policy_definition",
         ["g"] = "role_definition",
         ["e"] = "policy_effect",
         ["m"] = "matchers"
    }     

    self.requiredSections = {"r", "p", "e", "m"} -- Minimal required sections for a model to be valid
    self.modCount = 0   -- used by CoreEnforcer to detect changes to Model

    -- PolicyOperations: [key] = POLICY_ADD/POLICY_REMOVE and value = string(key)
    self.PolicyOperations = {
         POLICY_ADD = "POLICY_ADD",
         POLICY_REMOVE = "POLICY_REMOVE"
    }
    return o
end

function Model:getModCount()
     return self.modCount
end

function Model:loadAssertion(model, cfg, sec, key)
    local value = cfg:getString(self.sectionNameMap[sec].."::"..key)
    return model:addDef(sec, key, value)
end

--[[
     * addDef adds an assertion to the model.
     *
     * @param sec the section, "p" or "g".
     * @param key the policy type, "p", "p2", .. or "g", "g2", ..
     * @param value the policy rule, separated by ", ".
     * @return succeeds or not.
]]
function Model:addDef(sec, key, value)

     if value == "" then return false end

     if self.model[sec] == nil then
          self.model[sec] = {}
     end

     if self.model[sec][key] == nil then
          self.model[sec][key] = {}
     end

     self.model[sec][key] = Assertion:new()
     self.model[sec][key].key = key
     self.model[sec][key].value = value

     if sec == "r" or sec == "p" then
          self.model[sec][key].tokens = Util.splitCommaDelimited(self.model[sec][key].value)
          for k, v in pairs(self.model[sec][key].tokens) do
               self.model[sec][key].tokens[k] = key .. "_" .. self.model[sec][key].tokens[k]
          end
     else
          self.model[sec][key].value = Util.removeComments(Util.escapeAssertion(self.model[sec][key].value))
     end
     
     self.modCount = self.modCount + 1
     return true
end

function Model:getKeySuffix(i)
     if i == 1 then
          return ""
     end

     return ""..i
end

function Model:loadSection(model, cfg, sec)
    local i = 1
    while true do
        if not self:loadAssertion(model, cfg, sec, sec..self:getKeySuffix(i)) then
            break;
        else
            i = i + 1
        end
    end
end

--[[
     * loadModel loads the model from model CONF file.
     *
     * @param path the path of the model file.
]]
function Model:loadModel(path)
    local cfg = Config:newConfig(path)

    self:loadSection(self, cfg, "r")
    self:loadSection(self, cfg, "p")
    self:loadSection(self, cfg, "e")
    self:loadSection(self, cfg, "m")

    self:loadSection(self, cfg, "g")
end

--[[
     * loadModelFromText loads the model from the text.
     *
     * @param text the model text.
]]
function Model:loadModelFromText(text)
    local cfg = Config:newConfigFromText(text)

    self:loadSection(self, cfg, "r")
    self:loadSection(self, cfg, "p")
    self:loadSection(self, cfg, "e")
    self:loadSection(self, cfg, "m")

    self:loadSection(self, cfg, "g")
end

--[[
     * saveSectionToText saves the section to the text.
     *
     * @return the section text.
]]
function Model:saveSectionToText(sec)
     res = "[" .. self.sectionNameMap[sec] .. "]\n"

     if not self.model[sec] then
          return ""
     end

     for key, ast in pairs(self.model[sec]) do
          local val = ast.value:gsub("%_", ".")
          local x = string.format("%s = %s\n", key, val)

          res = res .. x
     end

     return res
end

--[[
     * saveModelToText saves the model to the text.
     *
     * @return the model text.
]]
function Model:saveModelToText()

end

--      * printModel prints the model to the log.
function Model:printModel()
     self.logger:info("Model: \n")
    for k,v in pairs(self.model) do
        for k2, v2 in pairs(v) do
            self.logger:info("[%s.%s]:", k, k2)
            self.logger:info(v2)
        end
    end
end

return Model
