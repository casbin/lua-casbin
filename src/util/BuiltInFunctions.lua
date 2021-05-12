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

local rex = require ("rex_pcre")
local posix = require("posix.fnmatch")

BuiltInFunctions = {}

-- Wrapper for keyMatch
function BuiltInFunctions.keyMatchFunc(args)
    if #args<2 then
        error("BuiltInFunctions should have atleast 2 arguments")
    end
    return BuiltInFunctions.keyMatch(args[1], args[2])
end

-- KeyMatch determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *.
-- For example, "/foo/bar" matches "/foo/*"
function BuiltInFunctions.keyMatch(key1, key2)
    local i, _ = string.find(key2, "*")

    if not i then
        return (key1 == key2)
    end

    if #key1>=i then
        return (string.sub(key1, 1, i-1) == string.sub(key2, 1, i-1))
    end
    return (key1 == string.sub(key2, 1, i-1))
end

-- Wrapper for keyGet
function BuiltInFunctions.keyGetFunc(args)
    if #args<2 then
        error("BuiltInFunctions should have atleast 2 arguments")
    end
    return BuiltInFunctions.keyGet(args[1], args[2])
end

-- KeyGet returns the matched part
-- For example, "/foo/bar/foo" matches "/foo/*"
-- "bar/foo" will been returned
function BuiltInFunctions.keyGet(key1, key2)
    local i, _ = string.find(key2, "*")

    if not i then
        return ""
    end
    if #key1>=i then
        if string.sub(key1, 1, i-1) == string.sub(key2, 1, i-1)  then
            return string.sub(key1, i)
        end
    end
    return ""
end

-- Wrapper for keyMatch2
function BuiltInFunctions.keyMatch2Func(args)
    if #args<2 then
        error("BuiltInFunctions should have atleast 2 arguments")
    end
    return BuiltInFunctions.keyMatch2(args[1], args[2])
end

-- KeyMatch2 determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *.
-- For example, "/foo/bar" matches "/foo/*", "/resource1" matches "/:resource"
function BuiltInFunctions.keyMatch2(key1, key2)
    key2 = string.gsub(key2, "/%*", "/.*")
    local key = rex.gsub(key2, ":[^/]+", "[^/]+")
	return BuiltInFunctions.regexMatch(key1, "^"..key.."$")
end

-- Wrapper for keyMatch3
function BuiltInFunctions.keyMatch3Func(args)
    if #args<2 then
        error("BuiltInFunctions should have atleast 2 arguments")
    end
    return BuiltInFunctions.keyMatch3(args[1], args[2])
end

-- KeyMatch3 determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *.
-- For example, "/foo/bar" matches "/foo/*", "/resource1" matches "/{resource}"
function BuiltInFunctions.keyMatch3(key1, key2)
    key2 = string.gsub(key2, "/%*", "/.*")
    local key = rex.gsub(key2, "{[^/]+}", "[^/]+")
	return BuiltInFunctions.regexMatch(key1, "^"..key.."$")
end

-- Wrapper for regexMatch
function BuiltInFunctions.regexMatchFunc(args)
    if #args<2 then
        error("BuiltInFunctions should have atleast 2 arguments")
    end
    return BuiltInFunctions.regexMatch(args[1], args[2])
end

-- RegexMatch determines whether key1 matches the pattern of key2 in regular expression.
function BuiltInFunctions.regexMatch(key1, key2)
    local res = rex.match(key1, key2)
    if res then
        return true
    else
        return false
    end
end

-- Wrapper for globMatch
function BuiltInFunctions.globMatchFunc(args)
    if #args<2 then
        error("BuiltInFunctions should have atleast 2 arguments")
    end
    return BuiltInFunctions.globMatch(args[1], args[2])
end

-- GlobMatch determines whether key1 matches the pattern of key2 using glob pattern
function BuiltInFunctions.globMatch(key1, key2)
    if posix.fnmatch(key2, key1, posix.FNM_PATHNAME or posix.FNM_PERIOD) == 0 then
        return true
    else
        return false
    end
end

-- GenerateGFunction is the factory method of the g(_, _) function.
function BuiltInFunctions.generateGFunction(rm)
    local function f(args)
        local name1 = args[1]
        local name2 = args[2]

        if not rm then
            return name1 == name2
        elseif #args==2 then
            return rm:hasLink(name1, name2)
        else
            local domain = args[3]
            return rm:hasLink(name1, name2, domain)
        end
    end

    return f
end