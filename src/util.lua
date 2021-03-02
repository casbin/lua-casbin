-- Utility Functions for lua-casbin

-- arrayToString convert table of strings to one string
function arrayToString(rule)
    local str = ""
    for i = 1, #rule do
        str = str .. ", " .. rule[i]
    end
    return str
end 
