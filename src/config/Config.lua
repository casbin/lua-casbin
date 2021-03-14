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

Config = {
    DEFAULT_SECTION = "default",
    DEFAULT_COMMENT = "#",
    DEFAULT_COMMENT_SEM = ";",
    data = {}
}

--[[
    * newConfig create an empty configuration representation from file.
    *
    * @param confName the path of the model file.
    * @return the constructor of Config.
]]
function Config:newConfig(confName)
    local c = {}
    setmetatable(c,self)
    self.__index = self
    c:parse(confName)
    return c
end

--[[
    * newConfigFromText create an empty configuration representation from text.
    *
    * @param text the model text.
    * @return the constructor of Config.
]]
function Config:newConfigFromText(text)
    
end

-- addConfig adds a new section->key:value to the configuration.
function Config:addConfig(section, option, value)
    
end

function Config:parse(fname)
    
end

function Config:parseBuffer()
    
end

-- getBool lookups up the value using the provided key and converts the value to a bool
function Config:getBool(key)
    
end

-- getNum lookups up the value using the provided key and converts the value to a number
function Config:getNum(key)
    
end

-- getString lookups up the value using the provided key and converts the value to a string
function Config:getString(key)
    
end

--[[
    Strings lookups up the value using the provided key and converts the value to an array
    of string by splitting the string by comma.
]]
function Config:getStrings(key)
    
end

-- Set sets the value for the specific key in the Config
function Config:set(key, value)
    
end

-- section.key or key
function Config:get(key)
    
end 
