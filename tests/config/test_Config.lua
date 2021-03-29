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

-- To run the test, use "lua test_Config.lua" and edit the 'path' on line 22

luaunit = require("luaunit")
require("src/config/Config")

testConfig = {}

local path = "{path to lua-casbin}/tests/config/test.ini" -- Enter the path to lua-casbin on your machine
local config = Config:newConfig(path)

function testConfig:testConfig()
    -- default::key
    luaunit.assertEquals(config:get("debug"), "true")
    luaunit.assertEquals(config:get("url"), "act.wiki")

    -- redis::key
    luaunit.assertEquals(config:get("redis::redis.key"), "push1,push2")
    luaunit.assertEquals(config:get("mysql::mysql.dev.host"), "127.0.0.1")
    luaunit.assertEquals(config:get("mysql::mysql.master.host"), "10.0.0.1")

    -- math::key test
    luaunit.assertEquals(config:get("math::math.i64"), "64")
    luaunit.assertEquals(config:get("math::math.f64"), "64.1")

    -- other::key test
    luaunit.assertEquals(config:get("other::name"), "ATC自动化测试^-^&($#……#")
    luaunit.assertEquals(config:get("other::key1"), "test key")

    -- set test
    config:set("other::key1", "new test key")
    luaunit.assertEquals(config:get("other::key1"), "new test key")
    config:set("other::key1", "test key")

    -- multi line test
    luaunit.assertEquals(config:get("multi1::name"), "r.sub==p.sub && r.obj==p.obj")
    luaunit.assertEquals(config:get("multi2::name"), "r.sub==p.sub && r.obj==p.obj")
    luaunit.assertEquals(config:get("multi3::name"), "r.sub==p.sub && r.obj==p.obj")
    luaunit.assertEquals(config:get("multi4::name"), "")
    luaunit.assertEquals(config:get("multi5::name"), "r.sub==p.sub && r.obj==p.obj")

    -- get{type} test
    luaunit.assertErrorMsgContains("Not a boolean value", config.getBool, config, "multi5::name")
    luaunit.assertEquals(config:getString("multi5::name"), "r.sub==p.sub && r.obj==p.obj")
    luaunit.assertEquals(config:getStrings("multi5::name"), {"r.sub==p.sub && r.obj==p.obj"})
    luaunit.assertErrorMsgContains("Not a num value", config.getNum, config, "multi5::name")
end

os.exit(luaunit.LuaUnit.run())
