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

require "src/Policy"
require "src/Assertion"
require "src/util"

Model = Policy:new()

function Model:new()
    o = Policy:new()
    setmetatable(o, self)
    self.__index = self

    self.sectionNameMap = {
         ["r"] = "request_definition",
         ["p"] = "policy_definition",
         ["g"] = "role_definition",
         ["e"] = "policy_effect",
         ["m"] = "matchers"
    }     

    self.requiredSections = {"r", "p", "e", "m"} -- Minimal required sections for a model to be valid
    self.modCount = 0   -- used by CoreEnforcer to detect changes to Model
    return o
end

function Model:getModCount()
     return self.modCount
end

function Model:loadAssertion(model, cfg, sec, key)

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
          self.model[sec][key].tokens = splitCommaDelimited(self.model[sec][key].value)
          for k,v in pairs(self.model[sec][key].tokens) do
               v = key .. "_" .. v
          end
     else
          self.model[sec][key].value = removeComments(escapeAssertion(self.model[sec][key].value))
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
     
end

--[[
     * loadModel loads the model from model CONF file.
     *
     * @param path the path of the model file.
]]
function Model:loadModel(path)

end

--[[
     * loadModelFromText loads the model from the text.
     *
     * @param text the model text.
]]
function Model:loadModelFromText(text)

end

--[[
     * saveSectionToText saves the section to the text.
     *
     * @return the section text.
]]
function Model:saveSectionToText(sec)

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

end

return Model
