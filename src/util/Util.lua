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
Util = {}

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
    str = str:gsub("% r%."," r_")
    str = str:gsub("% p%."," p_")
    str = str:gsub("%&r.","&r_")
    str = str:gsub("%&p.","&p_")
    str = str:gsub("%|r.","|r_")
    str = str:gsub("%|p.","|p_")
    str = str:gsub("%>r.",">r_")
    str = str:gsub("%>p.",">p_")
    str = str:gsub("%<r.","<r_")
    str = str:gsub("%<p.","<p_")
    str = str:gsub("%-r.","-r_")
    str = str:gsub("%-p.","-p_")
    str = str:gsub("%+r.","+r_")
    str = str:gsub("%+p.","+p_")
    str = str:gsub("%*r.","*r_")
    str = str:gsub("%*p.","*p_")
    str = str:gsub("%/r.","/r_")
    str = str:gsub("%/p.","/p_")
    str = str:gsub("%!r.","!r_")
    str = str:gsub("%!p.","!p_")
    str = str:gsub("%(r.","(r_")
    str = str:gsub("%(p.","(p_")
    str = str:gsub("%)r.",")r_")
    str = str:gsub("%)p.",")p_")
    str = str:gsub("%=r.","=r_")
    str = str:gsub("%=p.","=p_")
    str = str:gsub("%,r.",",r_")
    str = str:gsub("%,p.",",p_")
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
        return false
    end
    return true
end

return Util
