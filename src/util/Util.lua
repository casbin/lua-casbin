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

-- Utility Functions for lua-casbin
local Util = {}

-- arrayToString convert table of strings to one string
function Util.arrayToString(rule)
    local str = ""
    if #rule>0 then str = rule[1] end
    for i = 2, #rule do
        str = str .. ", " .. rule[i]
    end
    return str
end 

--[[
    * splitCommaDelimited splits a comma-delimited string into a string array. It assumes that any
    * number of whitespace might exist before or after the comma and that tokens do not include
    * whitespace as part of their value.
    *
    * @param str the comma-delimited string.
    * @return the array with the string tokens.
]]
function Util.splitCommaDelimited(str)
    str = str .. ","
    local t ={}
    for word in str:gmatch("([^,]+),%s*") do
         table.insert(t,Util.trim(word))
    end
    return t
end

--Escapes the dots in the assertion, because the expression evaluation doesn't support such variable names.
function Util.escapeAssertion(str)
    if string.sub(str, 1, 1) == "r" or string.sub(str, 1, 1) == "p" then
        str = str:gsub("%.","_", 1)
    end
    str = str:gsub("[^%w]+r%.", function (a)
        return string.sub(a, 1, -3).."r_"
    end)
    str = str:gsub("[^%w]+p%.", function (a)
        return string.sub(a, 1, -3).."p_"
    end)
    return str
end

--Removes the comments starting with # in the text.
function Util.removeComments(str)
    local i, _ = string.find(str, "#")
    if i then str = str:sub(1,i-1) end

    return Util.trim(str)
end

function Util.arrayEquals(a, b)
    if #a ~= #b then
        return false
    end
    for i = 1, #a do
        if a[i] ~= b[i] then
            return false
        end
    end
    return true
end

function Util.array2DEquals(a, b)
    if #a ~= #b then
        return false
    end
    for i = 1, #a do
        if not Util.arrayEquals(a[i], b[i]) then
            return false
        end
    end
    return true
end

function Util.arrayRemoveDuplications(s)
    local hash = {}
    local res = {}
    for _, v in pairs(s) do
        if not hash[v] then
            table.insert(res, v)
            hash[v] = true
        end
    end
    return res
end

-- Trims the leading and trailing whitespaces from a string
function Util.trim(s)
    return (s:gsub("^%s*(.-)%s*$", "%1"))
end

--[[
    * Splits string "str" with any "delimiter" and returns a table
    * (optional) 'x' is the maximum no. of times the string should be split
]]
function Util.split(str, delimiter, x)
    local result = {}
    local from  = 1
    local delim_from, delim_to = string.find(str, delimiter, from)
    while delim_from do
        table.insert(result, Util.trim(string.sub(str, from, delim_from-1)))
        from = delim_to + 1
        delim_from, delim_to = string.find(str, delimiter, from)
        if x~=nil then x = x - 1 end
        if x == 0 then break end
    end
    table.insert(result, Util.trim(string.sub(str, from)))
    return result
end

--[[
    * isInstance checks if o has parent as it's parent tables(metatables) recursively
    * @param base table, parent table
    * @returns true/false
]]
function Util.isInstance(o, parent)
    while o do
        o = getmetatable(o)
        if parent == o then return true end
    end
    return false
end

-- Searches if all values in a table are present in the other table regardless of order
function Util.areTablesSame(a, b)
    local c = {}
    for _, v in pairs(a) do
        if c[v] then
            c[v] = c[v] + 1
        else
            c[v] = 1
        end
    end

    for _, v in pairs(b) do
        if c[v] then
            c[v] = c[v] - 1
            if c[v] == 0 then
                c[v] = nil
            end
        else
            return false
        end
    end
    for _, v in pairs(c) do
        if v then
            return false
        end
    end
    return true
end

-- finds if string has eval and replaces eval(...) with its value so that it can be evaluated by luaxp
function Util.findAndReplaceEval(str, context)
    local m = string.gsub(str, "eval%((.-)%)", function (s)
        return Util.escapeAssertion(context[Util.trim(s)])
    end)
    return m
end

-- replaces [obj] in (obj1, obj2, ...) to obj == obj1 || obj == obj2 || ...
function Util.replaceInOfMatcher(str)
    local s = string.gsub(str, "([^%s]+)(%s+)in(%s+)%((.*)%)", function (a, _, _ , b)
        local t = ""
        local vals = Util.splitCommaDelimited(b)
        for k, v in pairs(vals) do
            t = t .. a .. " == " .. v
            if k<#vals then
                t = t .. " || "
            else
                t = t .. " "
            end
        end
        return t
    end)
    return s
end

-- returns deep (recursive) copy of a table (values only)
function Util.tableDeepCopy(org)
    local copy = {}
    for k, v in pairs(org) do
        if type(v) == "table" then
            copy[k] = Util.tableDeepCopy(v)
        else
            copy[k] = v
        end
    end
    return copy
end

-- setSubtract returns the elements in `a` that aren't in `b`.
function Util.setSubtract(a, b)
    local res = {}
    for _, v in pairs(a) do
        res[v] = true
    end
    for _, v in pairs(b) do
        if res[v] then
            res[v] = nil
        else
            res[v] = true
        end
    end
    local diff = {}
    for v, chk in pairs(res) do
        if chk == true then
            table.insert(diff, v)
        end
    end

    return diff
end

-- printTable recursively prints a table for logging
function Util.printTable(t)
    local s = "{ "
    for k, v in pairs(t) do
        if type(v) == "table" then
            s = s .. Util.printTable(v) .. ", "
        else
            if type(k)=="string" then
                s = s .. k .. " = " .. v .. ", "
            else
                s = s .. v .. ", "
            end
        end
    end
    s = string.sub(s, 1, -3)
    s = s .. " }"
    return s
end

function Util.loadPolicyLine(line, model)
    -- Loads a text line as a policy rule to model.

    if line == "" then
        return
    end

    if line:sub(1,1) == "#" then
        return
    end

    local tokens = Util.split(line, ",")
    local key = tokens[1]
    local sec = key:sub(1,1)

    if model.model[sec] == nil then
        return
    end
    if model.model[sec][key] == nil then
        return
    end

    model.model[sec][key].policy = model.model[sec][key].policy or {}
    model.model[sec][key].policyMap={}
    for i,policy in pairs(model.model[sec][key].policy) do
        model.model[sec][key].policyMap[table.concat(policy,",")]=i
    end
    local rules = {}
    for i = 2, #tokens do
        table.insert(rules, tokens[i])
    end
    table.insert(model.model[sec][key].policy, rules)
    model.model[sec][key].policyMap={}
    for i,policy in pairs(model.model[sec][key].policy) do
        model.model[sec][key].policyMap[table.concat(policy,",")]=i
    end
end


return Util