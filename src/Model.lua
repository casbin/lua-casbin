require "src/Policy"

Model = Policy:new()
--[[ private var ]]
model = {}
function Model:new()
    o = Policy:new()
    setmetatable(o, self)
    self.__index = self

    self.sectionNameMap = {}
    self.modCount = 0   -- used by CoreEnforcer to detect changes to Model
    return o
end

function Model:Model()
    model = {}
end

function Model:getModCount()

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

end

function Model:getKeySuffix(i)

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