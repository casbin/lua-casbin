Model2 = {
    area,
    length,
    breadth,
}

function Model2:new(o, length, breadth)
    o = o or {}
    setmetatable(o, self)
    self.__index = self
    self.length = length or 0
    self.breadth = breadth or 0
    self.area = length*breadth
    return o
end

function Model2:get()
    return self.area;
end


return Model2