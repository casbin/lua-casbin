Test = {
    area,
    length,
    breadth,
}

function Test:new(o, length, breadth)
    o = o or {}
    setmetatable(o, self)
    self.__index = self
    self.length = length or 0
    self.breadth = breadth or 0
    self.area = length*breadth
    return o
end

function Test:get()
    return self.area;
end


return Test