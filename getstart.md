# 开始使用

## 安装

<!--DOCUSAURUS_CODE_TABS-->

<!--Lua-->

```
luarocks install casbin  
/*
若出现Error: Your user does not have write permissions in /usr/local/lib/luarocks/rocks 
-- you may want to run as a privileged user or use your local tree with --local.
报错可使用
luarocks install casbin  --local
*/

```

<!--END_DOCUSAURUS_CODE_TABS-->

## 新建一个Casbin enforcer

Casbin使用配置文件来设置访问控制模型

它有两个配置文件, `model.conf` 和 `policy.csv`。 其中, `model.conf` 存储了我们的访问模型, 而 `policy.csv` 存储的是我们具体的用户权限配置。 Casbin的使用非常精炼。 基本上，我们只需要一种主要的结构：**enforcer** 当构造这个结构的时候， `model.conf` 和 `policy.csv` 将会被加载。

用另一种说法就是，当新建Casbin enforcer的时候 你必须提供一个 [Model](https://casbin.org/docs/zh-CN/supported-models) 和一个 [Adapter](https://casbin.org/docs/zh-CN/adapters)。

Casbin拥有一个 [FileAdapter](https://casbin.org/docs/zh-CN/adapters#file-adapter-built-in), 想知道更多请查阅 “更多Adapter” 中的[Adapter](https://casbin.org/docs/zh-CN/adapters)

- 使用Model文件和默认 [FileAdapter](https://casbin.org/docs/zh-CN/adapters#file-adapter-built-in):

<!--DOCUSAURUS_CODE_TABS-->

<!--Lua-->

```lua
lua_package_path "$prefix/lua/?.lua;$prefix/lua-casbin/?.lua;;";
local Enforcer = require("src.main.Enforcer")
local model  = "lua-casbin/examples/basic_model.conf" -- The model file path
local policy  = "lua-casbin/examples/basic_policy.csv" -- The policy file path
local e = Enforcer:new(model, policy) -- The Casbin Enforcer
```

- 与其他Adapter一起使用Model text

<!--END_DOCUSAURUS_CODE_TABS-->

### 检查权限

在访问发生之前，在代码中添加 enforcement hook

<!--DOCUSAURUS_CODE_TABS-->

<!--Lua-->

```lua
if e:enforce("alice", "data1", "read")
then
   --[ 允许alice读取data1 --]
else
   --[ 拒绝请求，抛出异常 --]
end

```

<!--END_DOCUSAURUS_CODE_TABS-->

请参阅 [Management API](https://casbin.org/docs/en/management-api) and [RBAC API](https://casbin.org/docs/en/rbac-api) 以获取更多使用方式。

请查看测试用例以获取更多使用方式。