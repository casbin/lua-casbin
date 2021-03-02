function loadPolicyLine(line, model)
     -- Loads a text line as a policy rule to model.

     if line == "" then
         return
     end
 
     if line:sub(1,1) == "#" then
         return
     end
 
     local tokens = {}
     for str in string.gmatch(line, '([^, ]+)') do
         table.insert(tokens,str)
     end
     local key = tokens[1]
     local sec = key:sub(1,1)
 
     if model.model[sec] == nil then
         return
     end
     if model.model[sec][key] == nil then
         return
     end
 
     model.model[sec][key].policy = model.model[sec][key].policy or {}
     local rules = {}
     for i = 2, #tokens do
         table.insert(rules, tokens[i])
     end
     table.insert(model.model[sec][key].policy, rules)
 end

--Adapter is the interface for Casbin adapters.
Adapter = {

}
Adapter.__index = Adapter
--[[
        * loadPolicy loads all policy rules from the storage.
        *
        * @param model the model.
]]
function Adapter:loadPolicy()

end

--[[
     * savePolicy saves all policy rules to the storage.
     *
     * @param model the model.
]]
function Adapter:savePolicy()

end

--[[
     * addPolicy adds a policy rule to the storage.
     * This is part of the Auto-Save feature.
     *
     * @param sec the section, "p" or "g".
     * @param ptype the policy type, "p", "p2", .. or "g", "g2", ..
     * @param rule the rule, like (sub, obj, act).
]]
function Adapter:addPolicy()

end

--[[
     * removePolicy removes a policy rule from the storage.
     * This is part of the Auto-Save feature.
     *
     * @param sec the section, "p" or "g".
     * @param ptype the policy type, "p", "p2", .. or "g", "g2", ..
     * @param rule the rule, like (sub, obj, act).
]]
function Adapter:removePolicy()

end

--[[
     * removeFilteredPolicy removes policy rules that match the filter from the storage.
     * This is part of the Auto-Save feature.
     *
     * @param sec the section, "p" or "g".
     * @param ptype the policy type, "p", "p2", .. or "g", "g2", ..
     * @param fieldIndex the policy rule's start index to be matched.
     * @param fieldValues the field values to be matched, value ""
     *                    means not to match this field.
]]
function Adapter:removeFilteredPolicy()

end

return Adapter
