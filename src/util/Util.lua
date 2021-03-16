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
require("logging")

Util = {}

Util.logger = logging.new(function(self, level, message)
    print(level, message)
    return true
end)

-- Whether to print logs or not.
Util.enableLog = true

-- arrayToString convert table of strings to one string
function Util.arrayToString(rule)
    local str = ""
    for i = 1, #rule do
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
    for word in s:gmatch("([^,]+),%s*") do
         table.insert(t,word)
    end
    return t
end

--Escapes the dots in the assertion, because the expression evaluation doesn't support such variable names.
function Util.escapeAssertion(str)
    str = str:gsub("%r.","r_",1)
    str = str:gsub("%p.","p_",1)

    return str
end

--Removes the comments starting with # in the text.
function Util.removeComments(str)
    local i, _ = string.find(str, "#")
    str = str:sub(1,i-1)

    return str
end

function Util.logPrint(v)
    if enableLog then
        Util.logger:info(v)
    end
end

function Util.logPrintf(format, ...)
    if enableLog then
        Util.logger.info(format, ...)
    end
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
        if ~Util.arrayEquals(a[i], b[i]) then
            return false
        end
    end
    return true
end

function Util.arrayRemoveDuplications(s)
    return true
end

-- Trims the leading and trailing whitespaces from a string
function Util.trim(s)
    return (s:gsub("^%s*(.-)%s*$", "%1"))
end

function Util.split(str, delimiter, x)
    local result = {}
    local from  = 1
    local delim_from, delim_to = string.find(str, delimiter, from)
    while delim_from do
        table.insert(result, string.sub(str, from, delim_from-1))
        from = delim_to + 1
        delim_from, delim_to = string.find(str, delimiter, from)
        if x~=nil then x = x - 1 end
        if x == 0 then break end
    end
    table.insert(result, string.sub(str, from))
    return result
end

return Util
