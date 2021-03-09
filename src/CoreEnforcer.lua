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