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

require "logging"
require "logging.file"

-- The logging module for logging to console or any file
Log = {}

-- returns logger function for logging to console
function Log:getLogger()
    local logger = logging.new(function(self, level, message)
        print(level, message)
        return true
      end)
    return logger
end

-- returns logger function for logging to file and @param: filePath = path of the log file
function Log:getFileLogger(filePath)
    if not filePath then
        error("no filePath for logger provided")
    end
    local logger = logging.file(filePath)
    return logger
end 
