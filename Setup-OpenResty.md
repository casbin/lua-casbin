# Installing Lua-Cabsin on OpenResty

## Installing OpenResty
You can follow [this guide](https://blog.openresty.com/en/ubuntu20-or-install/) to install OpenResty on Ubuntu 20.04 if you have not yet installed it.

## Installing and configuring LuaRocks
Run these commands in your terminal to install LuaRocks:
```
wget https://luarocks.org/releases/luarocks-3.3.1.tar.gz
tar zxpf luarocks-3.3.1.tar.gz
cd luarocks-3.3.1
```

To configure LuaRocks for OpenResty, run this command:
```
./configure --prefix=/usr/local/openresty/luajit \
--with-lua=/usr/local/openresty/luajit/ \
--lua-suffix=jit-2.1.0-beta3 \
--with-lua-include=/usr/local/openresty/luajit/include/luajit-2.1
```
and then this:
```
sudo make
sudo make install
```

**NOTE**: 
- This is assuming OpenResty (not the executable) is installed at `/usr/local/`, if it isn't so - replace `/usr/local/` with file path you have installed it in.
- Also assumed is that LuaJIT version is `2.1.0-beta3`, you can check which LuaJIT version it is by doing: `cd /usr/local/openresty/luajit/share/` and then `ls`. It will list a luajit folder like `luajit-2.1.0-beta3`, the suffix here is `jit-2.1.0-beta3`. If this isn't so, replace the suffix accordingly.

## Installing dependencies

You need to install GCC and PCRE as these are dependencies for `lualogging` module and `lrexlib-pcre` module.

To do so:
```
sudo apt update
sudo apt install gcc
sudo apt install libpcre3 libpcre3-dev
```

**NOTE**: If you use `yum` you could use `pcre` and `pcre-devel` for PCRE.

### Install LuaRocks modules

Run these commands to install the LuaRocks modules dependencies:
```
sudo /usr/local/openresty/luajit/bin/luarocks install lualogging
sudo /usr/local/openresty/luajit/bin/luarocks install lrexlib-pcre
sudo /usr/local/openresty/luajit/bin/luarocks install luaposix
```

**NOTE**: Here too the LuaRocks has its executable at `/usr/local/openresty/luajit/bin/luarocks`, if you have it installed somewhere else for OpenResty replace with that instead.

## Using Lua-Casbin

Since the project isn't a LuaRocks/OPM module yet, you need to clone it to use it.

**NOTE**: You may need to add the `nginx` command to your path by adding `export PATH="/usr/local/openresty/nginx/sbin/:$PATH"` to your `.bashrc` or similar file.
You can create a lua module for OpenResty applications as shown [here](https://blog.openresty.com/en/or-lua-module/) or add it to your existing lua module by following these steps:

- In your module, clone the Lua Casbin repo at the top level (`/`) of your application (along with the `conf` director) with `git clone https://github.com/casbin/lua-casbin.git`.
- In your module's `conf/nginx.conf` file append the `lua_package_path` with `$prefix/lua-casbin/?.lua;` so that it becomes something like this: `lua_package_path "$prefix/lua/?.lua;$prefix/lua-casbin/?.lua;;";`.
- In the file where you want to use Casbin, use `local Enforcer = require("src/main/Enforcer")` inside the `content_by_lua_block`. Here is a sample describing usage for basic model/policy and ABAC model/policy:

**Basic model/policy example (nginx.conf file)**
```
worker_processes 1;

events {
    worker_connections 1024;
}

http {
    lua_package_path "$prefix/lua/?.lua;$prefix/lua-casbin/?.lua;;";

    server {
        listen 8080 reuseport;

        location / {
            default_type text/plain;
            content_by_lua_block {
                local Enforcer = require("src.main.Enforcer")
                local model  = "lua-casbin/examples/basic_model.conf" -- The model file path
                local policy  = "lua-casbin/examples/basic_policy.csv" -- The policy file path
                
                local e = Enforcer:new(model, policy) -- The Casbin Enforcer
                ngx.say("The result is:")
                ngx.say(e:enforce("alice", "data1", "read")) -- The enforce function with its arguments
            }
        }
    }
}
```
**ABAC model/policy example (nginx.conf file)**
```
worker_processes 1;

events {
    worker_connections 1024;
}

http {
    lua_package_path "$prefix/lua/?.lua;$prefix/lua-casbin/?.lua;;";

    server {
        listen 8080 reuseport;

        location / {
            default_type text/plain;
            content_by_lua_block {
                local Enforcer = require("src.main.Enforcer")
                local model  = "lua-casbin/examples/abac_rule_model.conf"
    		local policy  = "lua-casbin/examples/abac_rule_policy.csv"
    		local sub1 = {
        		Name = "Alice",
        		Age = 16
    		}
    		local sub2 = {
        		Name = "Bob",
        		Age = 20
    		}
    		local sub3 = {
        		Name = "Alice",
        		Age = 65
    		}
    		local e = Enforcer:new(model, policy)
    		ngx.say("The result is:")
    		ngx.say(e:enforce(sub2, "/data1", "read"))
            }
        }
    }
}
```

Then use `nginx -p $PWD/` to start the server and use `curl http://127.0.0.1:8080/` to fetch the page which for the above examples should output in:
```
The result is:
true
```

You can check other examples [here](https://github.com/casbin/lua-casbin/blob/master/tests/main/enforcer_spec.lua) and the Built-In Functions currently supported [here](https://github.com/casbin/lua-casbin/blob/master/src/model/FunctionMap.lua).
