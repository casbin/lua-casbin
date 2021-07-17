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

local Shape = {
    area=0
}

function Shape:new(side)
    local o = {}
    setmetatable(o, self)
    self.__index = self
    side = side or 0
    self.area = side*side
    return o
end



function Shape:getarea()
    return self.area
end

return Shape


---- Model.lua
--
--require "src/Test"
--
--Model = Shape:new()
----Model.__index = Model
--ml = 3
--function Model:new(s,k)
--    o = Shape:new(s)
--    setmetatable(o, self)
--    self.k=k
--    self.__index = self
--    --self.area = s*k
--    return o
--end
--
--function Model:ge()
--    return self.area
--end
--
--function Model:g()
--    return ml
--end
--
--return Model
