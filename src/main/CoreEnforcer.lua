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

require("src.effect.DefaultEffector")
require("src.effect.Effector")
require("src.model.FunctionMap")
require("src.model.Model")
require("src.persist.file_adapter.FileAdapter")
require("src.rbac.DefaultRoleManager")
require("src.util.BuiltInFunctions")

local luaxp = require("modules.luaxp")

CoreEnforcer = {
    enabled = false,
    autoSave = false,
    autoBuildRoleLinks = false,
    autoNotifyWatcher = true,
    autoNotifyDispatcher = true,
}
CoreEnforcer.__index = CoreEnforcer

function CoreEnforcer:new(model, adapter)
    local o = {}
    setmetatable(o, self)
    self.__index = self
    self.logger = Log:getLogger()

    if type(model) == "string" then
        if type(adapter) == "string" then
            o:initWithFile(model, adapter)
        else
            o:initWithAdapter(model, adapter)
        end
    else
        if type(adapter) == "string" then
            error("Invalid parameters for Enforcer.")
        else
            o:initWithModelAndAdapter(model, adapter)
        end
    end
    return o
end

function CoreEnforcer:initWithFile(modelPath, policyPath)
    local a = FileAdapter:new(policyPath)
    self:initWithAdapter(modelPath, a)
end

function CoreEnforcer:initWithAdapter(modelPath, adapter)
    local m = self:newModel(modelPath)
    self:initWithModelAndAdapter(m, adapter)
    self.modelPath = modelPath
end

function CoreEnforcer:initWithModelAndAdapter(m, adapter)
    if not Util.isInstance(m, Model) or not Util.isInstance(adapter, Adapter) then
        error("Invalid parameters for Enforcer.")
    end

    self.adapter = adapter
    self.model = m
    self.model:printModel()

    self:initialize()
    if self.adapter and not self:isFiltered() then
        self:loadPolicy()
    end
end

function CoreEnforcer:initialize()
    self.rmMap = {}
    self.enabled = true
    self.autoSave = true
    self.autoBuildRoleLinks = true

    self:initBuildRoleLinks()
end

-- 
function CoreEnforcer:initBuildRoleLinks()
    if self.model.model["g"] then
        for ptype, _ in pairs(self.model.model["g"]) do
            self.rmMap[ptype] = DefaultRoleManager:new(10)
        end
    end
end

--[[
     * newModel creates a model.
     *
     * @param modelPath the path of the model file.
     * @param unused unused parameter, just for differentiating with
     *               newModel(String text).
     * @return the model.
]]
function CoreEnforcer:newModel(modelPath, text)
    local m = Model:new()
    if modelPath ~= "" then
        m:loadModel(modelPath)
    else
        m:loadModelFromText(text)
    end
    return m
end

--[[
     * loadModel reloads the model from the model CONF file.
     * Because the policy is attached to a model, so the policy is invalidated
     * and needs to be reloaded by calling LoadPolicy().
]]
function CoreEnforcer:loadModel()
    
end

--[[
     * getModel gets the current model.
     *
     * @return the model of the enforcer.
]]
function CoreEnforcer:getModel()
    return self.model
end

--[[
     * setModel sets the current model.
     *
     * @param model the model.
]]
function CoreEnforcer:setModel(model)
    self.model = model
end

--[[
     * getAdapter gets the current adapter.
     *
     * @return the adapter of the enforcer.
]]
function CoreEnforcer:getAdapter()
    return self.adapter
end

--[[
     * setAdapter sets the current adapter.
     *
     * @param adapter the adapter.
]]
function CoreEnforcer:setAdapter(adapter)
    self.adapter = adapter
end

--[[
     * setWatcher sets the current watcher.
     *
     * @param watcher the watcher.
]]
function CoreEnforcer:setWatcher(watcher)
    self.watcher = watcher
end

--[[
     * setDispatcher sets the current dispatcher.
     *
     * @param dispatcher jCasbin dispatcher
]]
function CoreEnforcer:setDispatcher(dispatcher)
    self.dispatcher = dispatcher
end

--[[
     * SetRoleManager sets the current role manager.
     *
     * @param rm the role manager.
]]
function CoreEnforcer:setRoleManager(rm)
    self.rm = rm
end

--[[
     * setEffector sets the current effector.
     *
     * @param eft the effector.
]]
function CoreEnforcer:setEffector(eft)
    self.eft = eft
end

--[[
     * clearPolicy clears all policy.
]]
function CoreEnforcer:clearPolicy()
    self.model:clearPolicy()
end

--[[
     * loadPolicy reloads the policy from file/database.
]]
function CoreEnforcer:loadPolicy()
    self.model:clearPolicy()
    self.adapter:loadPolicy(self.model);
    self.model:printPolicy()
    if self.autoBuildRoleLinks then
        self:buildRoleLinks()
    end
end

--[[
     * loadFilteredPolicy reloads a filtered policy from file/database.
     *
     * @param filter the filter used to specify which type of policy should be loaded.
]]
function CoreEnforcer:loadFilteredPolicy(filter)

end

--[[
     * isFiltered returns true if the loaded policy has been filtered.
     *
     * @return if the loaded policy has been filtered.
]]
function CoreEnforcer:isFiltered()
    return self.adapter.isFiltered
end

--[[
     * savePolicy saves the current policy (usually after changed with
     * Casbin API) back to file/database.
]]
function CoreEnforcer:savePolicy()

end

--[[
     * enableEnforce changes the enforcing state of Casbin, when Casbin is
     * disabled, all access will be allowed by the enforce() function.
     *
     * @param enable whether to enable the enforcer.
]]
function CoreEnforcer:enableEnforce(enable)
    self.enable = enable
end

--[[
     * enableLog changes whether to print Casbin log to the standard output.
     *
     * @param enable whether to enable Casbin's log.
]]
function CoreEnforcer:enableLog(enable)

end

--[[
     * enableAutoSave controls whether to save a policy rule automatically to
     * the adapter when it is added or removed.
     *
     * @param autoSave whether to enable the AutoSave feature.
]]
function CoreEnforcer:enableAutoSave(autoSave)
    self.autoSave = autoSave
end

--[[
     * enableAutoBuildRoleLinks controls whether to save a policy rule
     * automatically to the adapter when it is added or removed.
     *
     * @param autoBuildRoleLinks whether to automatically build the role links.
]]
function CoreEnforcer:enableAutoBuildRoleLinks(autoBuildRoleLinks)
    self.autoBuildRoleLinks  = autoBuildRoleLinks
end

--[[
     * buildRoleLinks manually rebuild the
     * role inheritance relations.
]]
function CoreEnforcer:buildRoleLinks()
    for _, rm in pairs(self.rmMap) do
        rm:clear()
    end

    self.model:buildRoleLinks(self.rmMap)
end

--[[
     * enforce decides whether a "subject" can access a "object" with
     * the operation "action", input parameters are usually: (sub, obj, act).
     *
     * @param rvals the request needs to be mediated, usually an array
     *              of strings, can be class instances if ABAC is used.
     * @return whether to allow the request.
]]
function CoreEnforcer:enforce(...)
    local rvals = {...}

    if not self.enabled then
        return false
    end
    
    local functions = FunctionMap:new()

    if self.model.model["g"] then
        for key, ast in pairs(self.model.model["g"]) do
            local rm = ast.RM
            functions[key] = BuiltInFunctions.generateGFunction(rm)
        end
    end

    if not self.model.model["m"] then
        error("model is undefined")
    end

    if not self.model.model["m"]["m"] then
        error("model is undefined")
    end

    local rTokens = self.model.model["r"]["r"].tokens
    local pTokens = self.model.model["p"]["p"].tokens

    if #rTokens ~= #rvals then
        error("invalid request size")
    end

    local expString = self.model.model["m"]["m"].value
    -- TODO: hasEval
    local policyLen = #self.model.model["p"]["p"].policy

    local policyEffects = {}

    if policyLen ~=0 then
        for i, pvals in pairs(self.model.model["p"]["p"].policy) do
            if #pTokens ~= #pvals then
                error("invalid policy size")
            end

            local context = {}
            for k, v in pairs(functions) do
                context[k] = v
            end
            for k, v in pairs(rTokens) do
                context[v] = rvals[k]
            end
            for k, v in pairs(pTokens) do
                context[v] = pvals[k]
            end

            local res, err = luaxp.evaluate(expString, context)
            if err then
                error("evaluation error: " .. err.message)
            end

            local c = true
            if type(res) == "boolean" then
                if not res then
                    table.insert(policyEffects, Effect.INDETERMINATE)
                    c = false
                end
            elseif type(res) == "number" then
                if res == 0 then
                    table.insert(policyEffects, Effect.INDETERMINATE)
                    c = false
                end
            else
                error("matcher result should be boolean or integer")
            end
            
            if context["p_eft"] and c then
                local eft = context["p_eft"]
                if eft == "allow" then
                    table.insert(policyEffects, Effect.ALLOW)
                elseif eft == "deny" then
                    table.insert(policyEffects, Effect.DENY)
                else
                    table.insert(policyEffects, Effect.INDETERMINATE)
                end
            elseif c then
                table.insert(policyEffects, Effect.ALLOW)
            end
        end
    else

    end
    
    local finalResult = DefaultEffector:mergeEffects(self.model.model["e"]["e"].value, policyEffects)
    return finalResult
end

function CoreEnforcer:isAutoNotifyWatcher()
    return self.autoNotifyWatcher
end

function CoreEnforcer:setAutoNotifyWatcher()
    self.autoNotifyWatcher = autoNotifyWatcher
end

function CoreEnforcer:isAutoNotifyDispatcher()
    return self.autoNotifyDispatcher
end

function CoreEnforcer:setAutoNotifyDispatcher(autoNotifyDispatcher)
    self.autoNotifyDispatcher = autoNotifyDispatcher
end

return CoreEnforcer
