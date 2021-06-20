# Get Started

## Installation

<!--DOCUSAURUS_CODE_TABS-->

<!--Lua-->

```
luarocks install casbin  
--[[ 
If report Error: Your user does not have write permissions in /usr/local/lib/luarocks/rocks 
-- you may want to run as a privileged user or use your local tree with --local.
you can add --local at your command like this:
luarocks install casbin  --local 
--]] 

```

<!--END_DOCUSAURUS_CODE_TABS-->

## New a Casbin enforcer

- Casbin uses configuration files to set the access control model.

  It has two configuration files, `model.conf` and `policy.csv`. Among them, `model.conf` stores our access model, and `policy.csv` stores our specific user permission configuration. The use of Casbin is very refined. Basically, we just need one main structure: **enforcer**. When constructing this structure, `model.conf` and `policy.csv` will be loaded.

  In another word, to new a Casbin enforcer, you must provide a [Model](https://casbin.org/docs/en/supported-models) and an [Adapter](https://casbin.org/docs/en/adapters).

  Casbin has a [FileAdapter](https://casbin.org/docs/en/adapters#file-adapter-built-in), see [Adapter](https://casbin.org/docs/en/adapters) from more Adapter.

  - Use the Model file and default [FileAdapter](https://casbin.org/docs/en/adapters#file-adapter-built-in):

<!--DOCUSAURUS_CODE_TABS-->

<!--Lua-->

```lua
lua_package_path "$prefix/lua/?.lua;$prefix/lua-casbin/?.lua;;";
local Enforcer = require("src.main.Enforcer")
local model  = "lua-casbin/examples/basic_model.conf" -- The model file path
local policy  = "lua-casbin/examples/basic_policy.csv" -- The policy file path
local e = Enforcer:new(model, policy) -- The Casbin Enforcer
```

- Use the Model text with other Adapter:

<!--END_DOCUSAURUS_CODE_TABS-->

### Check permissions

Add an enforcement hook into your code right before the access happens:

<!--DOCUSAURUS_CODE_TABS-->

<!--Lua-->

```lua
if e:enforce("alice", "data1", "read")
then
   --[ permit alice to read data1 --]
else
   --[ deny the request, show an error --]
end

```

<!--END_DOCUSAURUS_CODE_TABS-->

ee [Management API](https://casbin.org/docs/en/management-api) and [RBAC API](https://casbin.org/docs/en/rbac-api) for more usage.

Please refer to the test cases for more usage.