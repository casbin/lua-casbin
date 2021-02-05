CoreEnforcer = {
    model_path = 0,
    length = 0,
    breadth = 0,
}

function CoreEnforcer:new(o, length, breadth)
    o = o or {}
    setmetatable(o, self)
    self.__index = self
    self.length = length or 0
    self.breadth = breadth or 0
    self.area = length*breadth
    return o
end

function CoreEnforcer:get()
    return self.area;
end


return CoreEnforcer