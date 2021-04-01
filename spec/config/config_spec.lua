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

local config = require("src.config.Config")
local path = os.getenv("PWD") or io.popen("cd"):read()
path  = path .. "/spec/config/test.ini"
local config = Config:newConfig(path)

describe("config tests", function()

    it("test default::key", function()
        assert.are.equals(config:get("debug"), "true")
        assert.are.equals(config:get("url"), "act.wiki")
    end)

    it("test redis::key", function()
        assert.are.equals(config:get("redis::redis.key"), "push1,push2")
        assert.are.equals(config:get("mysql::mysql.dev.host"), "127.0.0.1")
        assert.are.equals(config:get("mysql::mysql.master.host"), "10.0.0.1")
    end)

    it("test math::key", function()
        assert.are.equals(config:get("math::math.i64"), "64")
        assert.are.equals(config:get("math::math.f64"), "64.1")
    end)

    it("test other::key", function()
        assert.are.equals(config:get("other::name"), "ATC自动化测试^-^&($#……#")
        assert.are.equals(config:get("other::key1"), "test key")
    end)

    it("test set", function()
        config:set("other::key1", "new test key")
        assert.are.equals(config:get("other::key1"), "new test key")
        config:set("other::key1", "test key")
    end)

    it("test multi line", function()
        assert.are.equals(config:get("multi1::name"), "r.sub==p.sub && r.obj==p.obj")
        assert.are.equals(config:get("multi2::name"), "r.sub==p.sub && r.obj==p.obj")
        assert.are.equals(config:get("multi3::name"), "r.sub==p.sub && r.obj==p.obj")
        assert.are.equals(config:get("multi4::name"), "")
        assert.are.equals(config:get("multi5::name"), "r.sub==p.sub && r.obj==p.obj")
    end)

    it("test get{type}", function()
        assert.are.equals(config:getString("multi5::name"), "r.sub==p.sub && r.obj==p.obj")
        assert.are.same(config:getStrings("multi5::name"), {"r.sub==p.sub && r.obj==p.obj"})
        assert.has_error(function () config:getBool("multi5::name") end, "Not a boolean value")
        assert.has_error(function () config:getNum("multi5::name") end, "Not a num value")
    end)

end) 
