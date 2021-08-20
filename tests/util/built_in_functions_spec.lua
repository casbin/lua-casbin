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

local BuiltInFunctions = require("src.util.BuiltInFunctions")

describe("BuiltInFunctions tests", function ()
    it("keyMatch tests", function ()
        assert.is.False(BuiltInFunctions.keyMatch("/foo", "/"))
        assert.is.True(BuiltInFunctions.keyMatch("/foo", "/foo"))
        assert.is.True(BuiltInFunctions.keyMatch("/foo", "/foo*"))
        assert.is.False(BuiltInFunctions.keyMatch("/foo", "/foo/*"))
        assert.is.False(BuiltInFunctions.keyMatch("/foo/bar", "/foo"))
        assert.is.True(BuiltInFunctions.keyMatch("/foo/bar", "/foo*"))
        assert.is.True(BuiltInFunctions.keyMatch("/foo/bar", "/foo/*"))
        assert.is.False(BuiltInFunctions.keyMatch("/foobar", "/foo"))
        assert.is.True(BuiltInFunctions.keyMatch("/foobar", "/foo*"))
        assert.is.False(BuiltInFunctions.keyMatch("/foobar", "/foo/*"))
    end)

    it("keyGet tests", function ()
        assert.are.same("", BuiltInFunctions.keyGet("/foo", "/foo"))
        assert.are.same("", BuiltInFunctions.keyGet("/foo", "/foo*"))
        assert.are.same("", BuiltInFunctions.keyGet("/foo", "/foo/*"))
        assert.are.same("", BuiltInFunctions.keyGet("/foo/bar", "/foo"))
        assert.are.same("/bar", BuiltInFunctions.keyGet("/foo/bar", "/foo*"))
        assert.are.same("bar", BuiltInFunctions.keyGet("/foo/bar", "/foo/*"))
        assert.are.same("", BuiltInFunctions.keyGet("/foobar", "/foo"))
        assert.are.same("bar", BuiltInFunctions.keyGet("/foobar", "/foo*"))
        assert.are.same("", BuiltInFunctions.keyGet("/foobar", "/foo/*"))
    end)

    it("keyMatch2 tests", function ()
        assert.is.False(BuiltInFunctions.keyMatch2("/foo", "/"))
        assert.is.True(BuiltInFunctions.keyMatch2("/foo", "/foo"))
        assert.is.True(BuiltInFunctions.keyMatch2("/foo", "/foo*"))
        assert.is.False(BuiltInFunctions.keyMatch2("/foo", "/foo/*"))
        assert.is.False(BuiltInFunctions.keyMatch2("/foo/bar", "/foo"))  -- different with KeyMatch.
        assert.is.False(BuiltInFunctions.keyMatch2("/foo/bar", "/foo*"))
        assert.is.True(BuiltInFunctions.keyMatch2("/foo/bar", "/foo/*"))
        assert.is.False(BuiltInFunctions.keyMatch2("/foobar", "/foo"))  -- different with KeyMatch.
        assert.is.False(BuiltInFunctions.keyMatch2("/foobar", "/foo*"))
        assert.is.False(BuiltInFunctions.keyMatch2("/foobar", "/foo/*"))

        assert.is.False(BuiltInFunctions.keyMatch2("/", "/:resource"))
        assert.is.True(BuiltInFunctions.keyMatch2("/resource1", "/:resource"))
        assert.is.False(BuiltInFunctions.keyMatch2("/myid", "/:id/using/:resId"))
        assert.is.True(BuiltInFunctions.keyMatch2("/myid/using/myresid", "/:id/using/:resId"))

        assert.is.False(BuiltInFunctions.keyMatch2("/proxy/myid", "/proxy/:id/*"))
        assert.is.True(BuiltInFunctions.keyMatch2("/proxy/myid/", "/proxy/:id/*"))
        assert.is.True(BuiltInFunctions.keyMatch2("/proxy/myid/res", "/proxy/:id/*"))
        assert.is.True(BuiltInFunctions.keyMatch2("/proxy/myid/res/res2", "/proxy/:id/*"))
        assert.is.True(BuiltInFunctions.keyMatch2("/proxy/myid/res/res2/res3", "/proxy/:id/*"))
        assert.is.False(BuiltInFunctions.keyMatch2("/proxy/", "/proxy/:id/*"))

        assert.is.True(BuiltInFunctions.keyMatch2("/alice", "/:id"))
        assert.is.True(BuiltInFunctions.keyMatch2("/alice/all", "/:id/all"))
        assert.is.False(BuiltInFunctions.keyMatch2("/alice", "/:id/all"))
        assert.is.False(BuiltInFunctions.keyMatch2("/alice/all", "/:id"))

        assert.is.False(BuiltInFunctions.keyMatch2("/alice/all", "/:/all"))
    end)

    it("keyMatch3 tests", function ()
        assert.is.True(BuiltInFunctions.keyMatch3("/foo", "/foo"))
        assert.is.True(BuiltInFunctions.keyMatch3("/foo", "/foo*"))
        assert.is.False(BuiltInFunctions.keyMatch3("/foo", "/foo/*"))
        assert.is.False(BuiltInFunctions.keyMatch3("/foo/bar", "/foo"))
        assert.is.False(BuiltInFunctions.keyMatch3("/foo/bar", "/foo*"))
        assert.is.True(BuiltInFunctions.keyMatch3("/foo/bar", "/foo/*"))
        assert.is.False(BuiltInFunctions.keyMatch3("/foobar", "/foo"))
        assert.is.False(BuiltInFunctions.keyMatch3("/foobar", "/foo*"))
        assert.is.False(BuiltInFunctions.keyMatch3("/foobar", "/foo/*"))

        assert.is.False(BuiltInFunctions.keyMatch3("/", "/{resource}"))
        assert.is.True(BuiltInFunctions.keyMatch3("/resource1", "/{resource}"))
        assert.is.False(BuiltInFunctions.keyMatch3("/myid", "/{id}/using/{resId}"))
        assert.is.True(BuiltInFunctions.keyMatch3("/myid/using/myresid", "/{id}/using/{resId}"))

        assert.is.False(BuiltInFunctions.keyMatch3("/proxy/myid", "/proxy/{id}/*"))
        assert.is.True(BuiltInFunctions.keyMatch3("/proxy/myid/", "/proxy/{id}/*"))
        assert.is.True(BuiltInFunctions.keyMatch3("/proxy/myid/res", "/proxy/{id}/*"))
        assert.is.True(BuiltInFunctions.keyMatch3("/proxy/myid/res/res2", "/proxy/{id}/*"))
        assert.is.True(BuiltInFunctions.keyMatch3("/proxy/myid/res/res2/res3", "/proxy/{id}/*"))
        assert.is.False(BuiltInFunctions.keyMatch3("/proxy/", "/proxy/{id}/*"))

        assert.is.False(BuiltInFunctions.keyMatch3("/myid/using/myresid", "/{id/using/{resId}"))
    end)

    it("keyMatch4 tests", function ()
        assert.is.True(BuiltInFunctions.keyMatch4("/parent/123/child/123", "/parent/{id}/child/{id}"))
        assert.is.False(BuiltInFunctions.keyMatch4("/parent/123/child/456", "/parent/{id}/child/{id}"))

        assert.is.True(BuiltInFunctions.keyMatch4("/parent/123/child/123", "/parent/{id}/child/{another_id}"))
        assert.is.True(BuiltInFunctions.keyMatch4("/parent/123/child/456", "/parent/{id}/child/{another_id}"))

        assert.is.True(BuiltInFunctions.keyMatch4("/parent/123/child/123/book/123", "/parent/{id}/child/{id}/book/{id}"))
        assert.is.False(BuiltInFunctions.keyMatch4("/parent/123/child/123/book/456", "/parent/{id}/child/{id}/book/{id}"))
        assert.is.False(BuiltInFunctions.keyMatch4("/parent/123/child/456/book/123", "/parent/{id}/child/{id}/book/{id}"))
        assert.is.False(BuiltInFunctions.keyMatch4("/parent/123/child/456/book/", "/parent/{id}/child/{id}/book/{id}"))
        assert.is.False(BuiltInFunctions.keyMatch4("/parent/123/child/456", "/parent/{id}/child/{id}/book/{id}"))

        assert.is.False(BuiltInFunctions.keyMatch4("/parent/123/child/123", "/parent/{i/d}/child/{i/d}"))
    end)

    it("regexMatch tests", function ()
        assert.is.True(BuiltInFunctions.regexMatch("/topic/create", "/topic/create"))
        assert.is.True(BuiltInFunctions.regexMatch("/topic/create/123", "/topic/create"))
        assert.is.False(BuiltInFunctions.regexMatch("/topic/delete", "/topic/create"))
        assert.is.False(BuiltInFunctions.regexMatch("/topic/edit", "/topic/edit/[0-9]+"))
        assert.is.True(BuiltInFunctions.regexMatch("/topic/edit/123", "/topic/edit/[0-9]+"))
        assert.is.False(BuiltInFunctions.regexMatch("/topic/edit/abc", "/topic/edit/[0-9]+"))
        assert.is.False(BuiltInFunctions.regexMatch("/foo/delete/123", "/topic/delete/[0-9]+"))
        assert.is.True(BuiltInFunctions.regexMatch("/topic/delete/0", "/topic/delete/[0-9]+"))
        assert.is.False(BuiltInFunctions.regexMatch("/topic/edit/123s", "/topic/delete/[0-9]+"))
    end)

    it("globMatch tests", function ()
        assert.is.True(BuiltInFunctions.globMatch("/foo", "/foo"))
        assert.is.True(BuiltInFunctions.globMatch("/foo", "/foo*"))
        assert.is.False(BuiltInFunctions.globMatch("/foo", "/foo/*"))
        assert.is.False(BuiltInFunctions.globMatch("/foo/bar", "/foo"))
        assert.is.False(BuiltInFunctions.globMatch("/foo/bar", "/foo*"))
        assert.is.True(BuiltInFunctions.globMatch("/foo/bar", "/foo/*"))
        assert.is.False(BuiltInFunctions.globMatch("/foobar", "/foo"))
        assert.is.True(BuiltInFunctions.globMatch("/foobar", "/foo*"))
        assert.is.False(BuiltInFunctions.globMatch("/foobar", "/foo/*"))

        assert.is.False(BuiltInFunctions.globMatch("/prefix/foo", "*/foo"))
        assert.is.False(BuiltInFunctions.globMatch("/prefix/foo", "*/foo*"))
        assert.is.False(BuiltInFunctions.globMatch("/prefix/foo", "*/foo/*"))
        assert.is.False(BuiltInFunctions.globMatch("/prefix/foo/bar", "*/foo"))
        assert.is.False(BuiltInFunctions.globMatch("/prefix/foo/bar", "*/foo*"))
        assert.is.False(BuiltInFunctions.globMatch("/prefix/foo/bar", "*/foo/*"))
        assert.is.False(BuiltInFunctions.globMatch("/prefix/foobar", "*/foo"))
        assert.is.False(BuiltInFunctions.globMatch("/prefix/foobar", "*/foo*"))
        assert.is.False(BuiltInFunctions.globMatch("/prefix/foobar", "*/foo/*"))

        assert.is.False(BuiltInFunctions.globMatch("/prefix/subprefix/foo", "*/foo"))
        assert.is.False(BuiltInFunctions.globMatch("/prefix/subprefix/foo", "*/foo*"))
        assert.is.False(BuiltInFunctions.globMatch("/prefix/subprefix/foo", "*/foo/*"))
        assert.is.False(BuiltInFunctions.globMatch("/prefix/subprefix/foo/bar", "*/foo"))
        assert.is.False(BuiltInFunctions.globMatch("/prefix/subprefix/foo/bar", "*/foo*"))
        assert.is.False(BuiltInFunctions.globMatch("/prefix/subprefix/foo/bar", "*/foo/*"))
        assert.is.False(BuiltInFunctions.globMatch("/prefix/subprefix/foobar", "*/foo"))
        assert.is.False(BuiltInFunctions.globMatch("/prefix/subprefix/foobar", "*/foo*"))
        assert.is.False(BuiltInFunctions.globMatch("/prefix/subprefix/foobar", "*/foo/*"))

    end)
end)