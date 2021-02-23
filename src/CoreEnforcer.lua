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
     * @return an empty model.
]]
function CoreEnforcer:newModel()

end

--[[
     * newModel creates a model.
     *
     * @param text the model text.
     * @return the model.
]]
function CoreEnforcer:newModel()

end


return CoreEnforcer