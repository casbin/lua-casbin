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

-- To run all the tests, use "lua test_Util.lua"

luaunit = require("luaunit")
require("lua-casbin/src/util/Util")

testUtil = {}

function testUtil:testArrayToString()
    luaunit.assertEquals(Util.arrayToString({"data", "data1", "data2", "data3"}), "data, data1, data2, data3")
end

function testUtil:testSplitCommaDelimited()
    luaunit.assertEquals(Util.splitCommaDelimited("a,b,c"), {"a", "b", "c"})
    luaunit.assertEquals(Util.splitCommaDelimited("a, b, c"), {"a", "b", "c"})
    luaunit.assertEquals(Util.splitCommaDelimited("a ,b ,c"), {"a", "b", "c"})
    luaunit.assertEquals(Util.splitCommaDelimited("  a,     b   ,c     "), {"a", "b", "c"})
end

function testUtil:testEscapeAssertion()
    luaunit.assertEquals(Util.escapeAssertion("r.attr.value == p.attr"),"r_attr.value == p_attr")
    luaunit.assertEquals(Util.escapeAssertion("r.attp.value || p.attr"),"r_attp.value || p_attr")
    luaunit.assertEquals(Util.escapeAssertion("r.attp.value &&p.attr"),"r_attp.value &&p_attr")
    luaunit.assertEquals(Util.escapeAssertion("r.attp.value >p.attr"),"r_attp.value >p_attr")
    luaunit.assertEquals(Util.escapeAssertion("r.attp.value <p.attr"),"r_attp.value <p_attr")
    luaunit.assertEquals(Util.escapeAssertion("r.attp.value -p.attr"),"r_attp.value -p_attr")
    luaunit.assertEquals(Util.escapeAssertion("r.attp.value +p.attr"),"r_attp.value +p_attr")
    luaunit.assertEquals(Util.escapeAssertion("r.attp.value *p.attr"),"r_attp.value *p_attr")
    luaunit.assertEquals(Util.escapeAssertion("r.attp.value /p.attr"),"r_attp.value /p_attr")
    luaunit.assertEquals(Util.escapeAssertion("!r.attp.value /p.attr"),"!r_attp.value /p_attr")
    luaunit.assertEquals(Util.escapeAssertion("g(r.sub, p.sub) == p.attr"),"g(r_sub, p_sub) == p_attr")
    luaunit.assertEquals(Util.escapeAssertion("g(r.sub,p.sub) == p.attr"),"g(r_sub,p_sub) == p_attr")
    luaunit.assertEquals(Util.escapeAssertion("(r.attp.value || p.attr)p.u"),"(r_attp.value || p_attr)p_u")
end

function testUtil:testRemoveComments()
    luaunit.assertEquals(Util.removeComments("r.act == p.act # comments"), "r.act == p.act")
    luaunit.assertEquals(Util.removeComments("r.act == p.act#comments"), "r.act == p.act")
    luaunit.assertEquals(Util.removeComments("r.act == p.act###"), "r.act == p.act")
    luaunit.assertEquals(Util.removeComments("### comments"), "")
    luaunit.assertEquals(Util.removeComments("r.act == p.act"), "r.act == p.act")
end

function testUtil:testArrayEquals()
    luaunit.assertEquals(Util.arrayEquals({"a", "b", "c"},{"a", "b", "c"}), true)
    luaunit.assertEquals(Util.arrayEquals({"a", "b", "c"},{"a", "b"}), false)
    luaunit.assertEquals(Util.arrayEquals({"a", "b", "c"},{"a", "c", "b"}), false)
    luaunit.assertEquals(Util.arrayEquals({"a", "b", "c"},{}), false)
end

function testUtil:testArray2DEquals()
    luaunit.assertEquals(Util.array2DEquals({{"a", "b", "c"}, {"1", "2", "3"}},{{"a", "b", "c"}, {"1", "2", "3"}}), true)
    luaunit.assertEquals(Util.array2DEquals({{"a", "b", "c"}, {"1", "2", "3"}}, {{"a", "b", "c"}}), false)
    luaunit.assertEquals(Util.array2DEquals({{"a", "b", "c"}, {"1", "2", "3"}}, {{"a", "b", "c"}, {"1", "2"}}), false)
    luaunit.assertEquals(Util.array2DEquals({{"a", "b", "c"}, {"1", "2", "3"}}, {{"1", "2", "3"}, {"a", "b", "c"}}), false)
    luaunit.assertEquals(Util.array2DEquals({{"a", "b", "c"}, {"1", "2", "3"}}, {}), false)
end

function testUtil:testArrayRemoveDuplications()
    luaunit.assertEquals(Util.arrayRemoveDuplications({"data", "data1", "data2", "data1", "data2", "data3"}),{'data', 'data1', 'data2', 'data3'})
end

function testUtil:testTrim()
    luaunit.assertEquals(Util.trim("abc"),"abc")
    luaunit.assertEquals(Util.trim(" abc "),"abc")
    luaunit.assertEquals(Util.trim("abc   "),"abc")
    luaunit.assertEquals(Util.trim("   abc"),"abc")
end

function testUtil:testSplit()
    luaunit.assertEquals(Util.split("a ,b ,c", ","), {"a", "b", "c"})
    luaunit.assertEquals(Util.split("a,b,c", ","), {"a", "b", "c"})
    luaunit.assertEquals(Util.split("a, b, c", ","), {"a", "b", "c"})
    luaunit.assertEquals(Util.split("  a,     b   ,c     ", ","), {"a", "b", "c"})
end

function testUtil:testIsInstance()
    local parent = {}
    parent.__index = parent
    local child = {}
    setmetatable(child, parent)
    local notChild = {}
    luaunit.assertEquals(Util.isInstance(child, parent), true)
    luaunit.assertEquals(Util.isInstance(notChildhild, parent), false)
end

os.exit(luaunit.LuaUnit.run())
