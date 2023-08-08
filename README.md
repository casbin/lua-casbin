# lua-casbin
[![GitHub Action](https://github.com/casbin/lua-casbin/workflows/build/badge.svg?branch=master)](https://github.com/casbin/lua-casbin/actions)
[![Coverage Status](https://coveralls.io/repos/github/casbin/lua-casbin/badge.svg?branch=master)](https://coveralls.io/github/casbin/lua-casbin?branch=master)
[![semantic-release](https://img.shields.io/badge/%20%20%F0%9F%93%A6%F0%9F%9A%80-semantic--release-e10079.svg)](https://github.com/semantic-release/semantic-release)
[![Discord](https://img.shields.io/discord/1022748306096537660?logo=discord&label=discord&color=5865F2)](https://discord.gg/S5UjpzGZjN)

[![LuaRocks](https://img.shields.io/luarocks/v/hsluoyz/casbin.svg)](https://luarocks.org/modules/hsluoyz/casbin)
[![Generic badge](https://img.shields.io/badge/Lua-5.1-44cc11.svg)](https://shields.io/)
[![Generic badge](https://img.shields.io/badge/Lua-5.2-44cc11.svg)](https://shields.io/)
[![Generic badge](https://img.shields.io/badge/Lua-5.3-44cc11.svg)](https://shields.io/)
[![Generic badge](https://img.shields.io/badge/Lua-5.4-44cc11.svg)](https://shields.io/)
[![Generic badge](https://img.shields.io/badge/LuaJIT-2.0-44cc11.svg)](https://shields.io/)


An authorization library that supports access control models like ACL, RBAC, ABAC in Lua (OpenResty)

Read the setup guide for OpenResty [here](https://github.com/casbin-lua/lua-resty-casbin/).

**News**: Are you still worried about how to write the correct Casbin policy? ``Casbin online editor`` is coming to help! Try it at: http://casbin.org/editor/

![casbin Logo](casbin-logo.png)

## All the languages supported by Casbin:

[![golang](https://casbin.org/img/langs/golang.png)](https://github.com/casbin/casbin) | [![java](https://casbin.org/img/langs/java.png)](https://github.com/casbin/jcasbin) | [![nodejs](https://casbin.org/img/langs/nodejs.png)](https://github.com/casbin/node-casbin) | [![php](https://casbin.org/img/langs/php.png)](https://github.com/php-casbin/php-casbin)
----|----|----|----
[Casbin](https://github.com/casbin/casbin) | [jCasbin](https://github.com/casbin/jcasbin) | [node-Casbin](https://github.com/casbin/node-casbin) | [PHP-Casbin](https://github.com/php-casbin/php-casbin)
production-ready | production-ready | production-ready | production-ready

[![python](https://casbin.org/img/langs/python.png)](https://github.com/casbin/pycasbin) | [![dotnet](https://casbin.org/img/langs/dotnet.png)](https://github.com/casbin-net/Casbin.NET) | [![c++](https://casbin.org/img/langs/cpp.png)](https://github.com/casbin/casbin-cpp) | [![rust](https://casbin.org/img/langs/rust.png)](https://github.com/casbin/casbin-rs)
----|----|----|----
[PyCasbin](https://github.com/casbin/pycasbin) | [Casbin.NET](https://github.com/casbin-net/Casbin.NET) | [Casbin-CPP](https://github.com/casbin/casbin-cpp) | [Casbin-RS](https://github.com/casbin/casbin-rs)
production-ready | production-ready | beta-test | production-ready

## Installation

```bash
sudo luarocks install casbin
```

## Get Started

1. New Casbin enforcer with a model file and a policy file:
```lua
local Enforcer = require("casbin")
local e = Enforcer:new("path/to/model.conf", "path/to/policy.csv")
```
Note: you can also initialize an enforcer with policy in DB instead of file, see [Policy-persistence](https://github.com/casbin/lua-casbin#policy-persistence) section for details.

2. Add an enforcement hook into your code right before the access happens:
```lua
local sub = "alice" -- the user that wants to access a resource.
local obj = "data1" -- the resource that is going to be accessed.
local act = "read" -- the operation that the user performs on the resource.

if e:enforce(sub, obj, act) then
    -- permit alice to read data1
else
    -- deny the request, show an error
end
```

3. Besides the static policy file, Casbin also provides API for permission management at run-time. For example, You can get all the roles assigned to a user as below:
```lua
local roles = e:GetImplicitRolesForUser(sub)
```
See [Policy management APIs](https://github.com/casbin/lua-casbin#policy-management) for more usage.


## Supported models

1. [**ACL (Access Control List)**](https://en.wikipedia.org/wiki/Access_control_list)
2. **ACL with [superuser](https://en.wikipedia.org/wiki/Superuser)**
3. **ACL without users**: especially useful for systems that don't have authentication or user log-ins.
3. **ACL without resources**: some scenarios may target for a type of resources instead of an individual resource by using permissions like ``write-article``, ``read-log``. It doesn't control the access to a specific article or log.
4. **[RBAC (Role-Based Access Control)](https://en.wikipedia.org/wiki/Role-based_access_control)**
5. **RBAC with resource roles**: both users and resources can have roles (or groups) at the same time.
6. **RBAC with domains/tenants**: users can have different role sets for different domains/tenants.
7. **[ABAC (Attribute-Based Access Control)](https://en.wikipedia.org/wiki/Attribute-Based_Access_Control)**: syntax sugar like ``resource.Owner`` can be used to get the attribute for a resource.
8. **[RESTful](https://en.wikipedia.org/wiki/Representational_state_transfer)**: supports paths like ``/res/*``, ``/res/:id`` and HTTP methods like ``GET``, ``POST``, ``PUT``, ``DELETE``.
9. **Deny-override**: both allow and deny authorizations are supported, deny overrides the allow.
10. **Priority**: the policy rules can be prioritized like firewall rules.

## How it works?

In Casbin, an access control model is abstracted into a CONF file based on the **PERM metamodel (Policy, Effect, Request, Matchers)**. So switching or upgrading the authorization mechanism for a project is just as simple as modifying a configuration. You can customize your own access control model by combining the available models. For example, you can get RBAC roles and ABAC attributes together inside one model and share one set of policy rules.

The most basic and simplest model in Casbin is ACL. ACL's model CONF is:

```ini
# Request definition
[request_definition]
r = sub, obj, act

# Policy definition
[policy_definition]
p = sub, obj, act

# Policy effect
[policy_effect]
e = some(where (p.eft == allow))

# Matchers
[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act

```

An example policy for ACL model is like:

```
p, alice, data1, read
p, bob, data2, write
```

It means:

- alice can read data1
- bob can write data2

## Features

What Casbin does:

1. enforce the policy in the classic ``{subject, object, action}`` form or a customized form as you defined, both allow and deny authorizations are supported.
2. handle the storage of the access control model and its policy.
3. manage the role-user mappings and role-role mappings (aka role hierarchy in RBAC).
4. support built-in superuser like ``root`` or ``administrator``. A superuser can do anything without explict permissions.
5. multiple built-in operators to support the rule matching. For example, ``keyMatch`` can map a resource key ``/foo/bar`` to the pattern ``/foo*``.

What Casbin does NOT do:

1. authentication (aka verify ``username`` and ``password`` when a user logs in)
2. manage the list of users or roles. I believe it's more convenient for the project itself to manage these entities. Users usually have their passwords, and Casbin is not designed as a password container. However, Casbin stores the user-role mapping for the RBAC scenario.

## Documentation

https://casbin.org/docs/overview

## Online editor

You can also use the online editor (https://casbin.org/editor/) to write your Casbin model and policy in your web browser. It provides functionality such as ``syntax highlighting`` and ``code completion``, just like an IDE for a programming language.

## Tutorials

https://casbin.org/docs/tutorials

## Policy management

Casbin provides two sets of APIs to manage permissions:

- [Management API](https://casbin.org/docs/management-api): the primitive API that provides full support for Casbin policy management.
- [RBAC API](https://casbin.org/docs/rbac-api): a more friendly API for RBAC. This API is a subset of Management API. The RBAC users could use this API to simplify the code.

We also provide a [web-based UI](https://casbin.org/docs/admin-portal) for model management and policy management:

![model editor](https://hsluoyz.github.io/casbin/ui_model_editor.png)

![policy editor](https://hsluoyz.github.io/casbin/ui_policy_editor.png)

## Policy persistence

https://casbin.org/docs/adapters

## Policy consistence between multiple nodes

https://casbin.org/docs/watchers

## Role manager

https://casbin.org/docs/role-managers

## Examples

Model | Model file | Policy file
----|------|----
ACL | [basic_model.conf](https://github.com/casbin/casbin/blob/master/examples/basic_model.conf) | [basic_policy.csv](https://github.com/casbin/casbin/blob/master/examples/basic_policy.csv)
ACL with superuser | [basic_model_with_root.conf](https://github.com/casbin/casbin/blob/master/examples/basic_with_root_model.conf) | [basic_policy.csv](https://github.com/casbin/casbin/blob/master/examples/basic_policy.csv)
ACL without users | [basic_model_without_users.conf](https://github.com/casbin/casbin/blob/master/examples/basic_without_users_model.conf) | [basic_policy_without_users.csv](https://github.com/casbin/casbin/blob/master/examples/basic_without_users_policy.csv)
ACL without resources | [basic_model_without_resources.conf](https://github.com/casbin/casbin/blob/master/examples/basic_without_resources_model.conf) | [basic_policy_without_resources.csv](https://github.com/casbin/casbin/blob/master/examples/basic_without_resources_policy.csv)
RBAC | [rbac_model.conf](https://github.com/casbin/casbin/blob/master/examples/rbac_model.conf)  | [rbac_policy.csv](https://github.com/casbin/casbin/blob/master/examples/rbac_policy.csv)
RBAC with resource roles | [rbac_model_with_resource_roles.conf](https://github.com/casbin/casbin/blob/master/examples/rbac_with_resource_roles_model.conf)  | [rbac_policy_with_resource_roles.csv](https://github.com/casbin/casbin/blob/master/examples/rbac_with_resource_roles_policy.csv)
RBAC with domains/tenants | [rbac_model_with_domains.conf](https://github.com/casbin/casbin/blob/master/examples/rbac_with_domains_model.conf)  | [rbac_policy_with_domains.csv](https://github.com/casbin/casbin/blob/master/examples/rbac_with_domains_policy.csv)
ABAC | [abac_model.conf](https://github.com/casbin/casbin/blob/master/examples/abac_model.conf)  | N/A
RESTful | [keymatch_model.conf](https://github.com/casbin/casbin/blob/master/examples/keymatch_model.conf)  | [keymatch_policy.csv](https://github.com/casbin/casbin/blob/master/examples/keymatch_policy.csv)
Deny-override | [rbac_model_with_deny.conf](https://github.com/casbin/casbin/blob/master/examples/rbac_with_deny_model.conf)  | [rbac_policy_with_deny.csv](https://github.com/casbin/casbin/blob/master/examples/rbac_with_deny_policy.csv)
Priority | [priority_model.conf](https://github.com/casbin/casbin/blob/master/examples/priority_model.conf)  | [priority_policy.csv](https://github.com/casbin/casbin/blob/master/examples/priority_policy.csv)

## Middlewares

Authz middlewares for web frameworks: https://casbin.org/docs/middlewares

## Our adopters

https://casbin.org/docs/adopters

## How to Contribute

Please read the [contributing guide](CONTRIBUTING.md).

## Backers

Thank you to all our backers! 🙏 [[Become a backer](https://opencollective.com/casbin#backer)]

<a href="https://opencollective.com/casbin#backers" target="_blank"><img src="https://opencollective.com/casbin/backers.svg?width=890"></a>

## Sponsors

Support this project by becoming a sponsor. Your logo will show up here with a link to your website. [[Become a sponsor](https://opencollective.com/casbin#sponsor)]

<a href="https://opencollective.com/casbin/sponsor/0/website" target="_blank"><img src="https://opencollective.com/casbin/sponsor/0/avatar.svg"></a>
<a href="https://opencollective.com/casbin/sponsor/1/website" target="_blank"><img src="https://opencollective.com/casbin/sponsor/1/avatar.svg"></a>
<a href="https://opencollective.com/casbin/sponsor/2/website" target="_blank"><img src="https://opencollective.com/casbin/sponsor/2/avatar.svg"></a>
<a href="https://opencollective.com/casbin/sponsor/3/website" target="_blank"><img src="https://opencollective.com/casbin/sponsor/3/avatar.svg"></a>
<a href="https://opencollective.com/casbin/sponsor/4/website" target="_blank"><img src="https://opencollective.com/casbin/sponsor/4/avatar.svg"></a>
<a href="https://opencollective.com/casbin/sponsor/5/website" target="_blank"><img src="https://opencollective.com/casbin/sponsor/5/avatar.svg"></a>
<a href="https://opencollective.com/casbin/sponsor/6/website" target="_blank"><img src="https://opencollective.com/casbin/sponsor/6/avatar.svg"></a>
<a href="https://opencollective.com/casbin/sponsor/7/website" target="_blank"><img src="https://opencollective.com/casbin/sponsor/7/avatar.svg"></a>
<a href="https://opencollective.com/casbin/sponsor/8/website" target="_blank"><img src="https://opencollective.com/casbin/sponsor/8/avatar.svg"></a>
<a href="https://opencollective.com/casbin/sponsor/9/website" target="_blank"><img src="https://opencollective.com/casbin/sponsor/9/avatar.svg"></a>

## License

This project is licensed under the [Apache 2.0 license](LICENSE).

## Contact

If you have any issues or feature requests, please contact us. PR is welcomed.
- https://github.com/casbin/lua-casbin/issues
- hsluoyz@gmail.com
- Tencent QQ group: [546057381](//shang.qq.com/wpa/qunwpa?idkey=8ac8b91fc97ace3d383d0035f7aa06f7d670fd8e8d4837347354a31c18fac885)
