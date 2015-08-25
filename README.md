# BuildBot-OpenID
OpenID Authorization/Authentication plugin for BuildBot

Note: More documentation coming up.

Note2: This code is for BuildBot version 8.


## How to configure
In master.cfg, replace the authz_cfg= line with something like

```
authz_cfg=openidauthz.OpenIDAuthZ(
    openid_provider='https://id.fedoraproject.org/openid/',
    _all_=['view'],
    _authenticated_=['pingBuilder'],
    sysadmin=['stopBuild', 'gracefulShutdown'],
    releng=['forceBuild']
)
```
