
--Adapter is the interface for Casbin adapters.
Adapter = {

}
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