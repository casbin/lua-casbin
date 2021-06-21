package = "casbin"
version = "0.0.1-1"
source = {
   url = "git://github.com/casbin/lua-casbin.git"
}
description = {
   summary = "An authorization library that supports access control models like ACL, RBAC, ABAC in Lua (OpenResty)",
   detailed = [[
      An authorization library that supports access control models like ACL, RBAC, ABAC in Lua (OpenResty)
   ]],
   detailed = "An authorization library that supports access control models like ACL, RBAC, ABAC in Lua (OpenResty)",
   homepage = "https://github.com/casbin/lua-casbin",
   license = "Apache License 2.0",
   maintainer = "admin@casbin.org"
}
dependencies = {
   "lua >= 5.1"
}
build = {
   type = "builtin",
   modules = {
      Test = "src/Test.lua",
      ["config.Config"] = "src/config/Config.lua",
      ["effect.DefaultEffector"] = "src/effect/DefaultEffector.lua",
      ["effect.Effect"] = "src/effect/Effect.lua",
      ["effect.Effector"] = "src/effect/Effector.lua",
      ["main.CoreEnforcer"] = "src/main/CoreEnforcer.lua",
      ["main.Enforcer"] = "src/main/Enforcer.lua",
      ["model.Assertion"] = "src/model/Assertion.lua",
      ["model.Model"] = "src/model/Model.lua",
      ["model.Policy"] = "src/model/Policy.lua",
      ["persist.Adapter"] = "src/persist/Adapter.lua",
      ["persist.FilteredAdapter"] = "src/persist/FilteredAdapter.lua",
      ["persist.file_adapter.FileAdapter"] = "src/persist/file_adapter/FileAdapter.lua",
      ["persist.file_adapter.FilteredAdapter"] = "src/persist/file_adapter/FilteredAdapter.lua",
      ["rbac.DefaultRoleManager"] = "src/rbac/DefaultRoleManager.lua",
      ["rbac.DomainRoles"] = "src/rbac/DomainRoles.lua",
      ["rbac.Role"] = "src/rbac/Role.lua",
      ["rbac.RoleManager"] = "src/rbac/RoleManager.lua",
      ["util.Util"] = "src/util/Util.lua"
   }
}