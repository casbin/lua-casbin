Shape = {
    area=0
}

function Shape:new(side)
    o = {}
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