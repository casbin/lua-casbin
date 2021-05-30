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

local log = require("src.util.Log")
local path = os.getenv("PWD") or io.popen("cd"):read()
path = path .. "/testLogFile.log"

describe("log tests", function ()
    
    it("test console logger", function ()
        local logger = Log:getLogger()
        assert.has_no.errors(function ()
            logger:info("logging to console")
        end)
    end)

    it("test file logger", function ()
        local logger = Log:getFileLogger(path)
        logger:info("new log started")
        assert.has_no.errors(function ()
            io.open(path, "r")
        end)
    end)

    it("test filePath error", function ()
        assert.has_error(function ()
            local logger = Log:getFileLogger()
        end)
    end)
end) 
