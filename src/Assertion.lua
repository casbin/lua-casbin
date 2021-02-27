require "src/RoleManager"
--[[
    * Assertion represents an expression in a section of the model.
    * For example: r = sub, obj, act
]]
Assertion = {
    key,
    value,
    tokens,
    policy,
    RM
}

function Assertion:buildRoleLinks(rm)
    self.RM = rm
    local count = 0
    for i = 1, string.len(value) do
        if string.sub(value,i,i) == '_' then
            count = count + 1
        end
    end

    for _, rule in pairs(self.policy) do
        if count < 2 then
            error("the number of \"_\" in role definition should be at least 2")
        end

        if #rule < count then
            error("grouping policy elements do not meet role definition")
        end
        
        local name1, name2 = nil 
        local domain = {}
        for i, string in pairs(rule) do
            if i > count then break end

            if name1 == nil then
                name1 = string
            elseif name2 == nil then
                name2 = string
            else
                table.insert(domain,string)
            end
        end

        self.RM.addLink(name1, name2, domain)
    end

end

function Assertion:buildIncrementalRoleLinks(rm, op, rules)
    self.RM = rm
    local count = 0
    for i = 1, string.len(value) do
        if string.sub(value,i,i) == '_' then
            count = count + 1
        end
    end

    for _, rule in pairs(rules) do
        if count < 2 then
            error("the number of \"_\" in role definition should be at least 2")
        end

        if #rule < count then
            error("grouping policy elements do not meet role definition")
        end
        
        local name1, name2 = nil 
        local domain = {}
        for i, string in pairs(rule) do
            if i > count then break end

            if name1 == nil then
                name1 = string
            elseif name2 == nil then
                name2 = string
            else
                table.insert(domain,string)
            end
        end

        if op == POLICY_ADD then
            self.RM.addLink(name1, name2, domain)
        elseif op == POLICY_REMOVE then
            self.RM.deleteLink(name1, name2, domain)
        else
            error("invalid operation")
        end
    end
end
