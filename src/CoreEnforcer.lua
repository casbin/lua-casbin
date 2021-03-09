CoreEnforcer = {
    model_path,
    model,
    fm,
    adapter,
    watcher,
    rm,
    dispatcher,
    autoSave,
    autoBuildRoleLinks,
    autoNotifyWatcher = true,
    autoNotifyDispatcher = true,
    aviatorEval,    -- cached instance of AviatorEvaluatorInstance
    modelModCount,  -- detect changes in Model so that we can invalidate AviatorEvaluatorInstance cache
}

--[[
private:
    Effector eft
    boolean enabled
]]

local function initialize()

end

--[[
     * newModel creates a model.
     *
     * @param text the model text.
     * @return the model.
]]
function CoreEnforcer:newModel(text)
    m = Model:Model()
    if text~=nil then
        m.loadModelFromText(text);
    end
    return m
end

--[[
     * newModelFromPath creates a model.
     *
     * @param modelPath the path of the model file.
     * @param unused unused parameter, just for differentiating with
     *               newModel(String text).
     * @return the model.
]]
function CoreEnforcer:newModelFromPath(modelPath, unused)
    m = Model:Model()
    if modelPath~='' then
        m.loadModel(text);
    end
    return m
end

--[[
     * loadModel reloads the model from the model CONF file.
     * Because the policy is attached to a model, so the policy is invalidated
     * and needs to be reloaded by calling LoadPolicy().
]]
function CoreEnforcer:loadModel()
    model = self:newModel()
    model:loadModel(self.modelPath)
    model:printModel()
    self.fm = FunctionMap:loadFunctionMap();
    self.aviatorEval = nil
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
    self.fm = FunctionMap:loadFunctionMap();
    self.aviatorEval = nil
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
    watcher:setUpdateCallback(loadPolicy())
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
    self.adapter:loadPolicy(model);
    self.model:printPolicy()
    if autoBuildRoleLinks then
        buildRoleLinks()
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
    self.rm.clear()
    self.model.buildRoleLinks(rm)
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

end


function CoreEnforcer:getRTokens(parameters, ...)

end

function CoreEnforcer:validateEnforce(...)

end

function CoreEnforcer:validateEnforceSection(section, ...)

end

--[[
     * Invalidate cache of compiled model matcher expression. This is done automatically most of the time, but you may
     * need to call it explicitly if you manipulate directly Model.
]]
function CoreEnforcer:resetExpressionEvaluator()
    self.aviatorEval = null
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