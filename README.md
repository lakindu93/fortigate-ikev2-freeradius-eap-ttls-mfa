# fortigate-eap-ttls-asgardeo-mfa

FreeRADIUS 3.2 configuration for a FortiGate IKEv2 IPsec dial-up VPN using
EAP-TTLS, with:

- **Password validation** delegated to a WSO2 Asgardeo tenant (Resource
  Owner Password Credentials grant against the Asgardeo OAuth2 token
  endpoint)
- **TOTP MFA** (Google Authenticator-compatible) enforced server-side,
  appended to the end of the password in the EAP-TTLS inner PAP exchange
  (`<password><6-digit-code>`)
- **Group-based access control**: the user's Asgardeo group is mapped to a
  `Fortinet-Group-Name` reply attribute, which FortiGate uses to place the
  session into the matching `config user group`

## Architecture

```
FortiClient  --IKEv2/EAP-TTLS-->  FortiGate  --RADIUS-->  FreeRADIUS
                                                  |
                                          inner-tunnel (PAP)
                                                  |
                                        mods-config/python3/radius_policy.py
                                           |                    |
                                  Asgardeo (ROPC +      otp_check.py
                                  userinfo/groups)       (local TOTP)
```

The outer EAP-TTLS TLS tunnel is terminated locally by this RADIUS server
(not proxied anywhere). Inside the tunnel, `radius_policy.py` runs as a
`python3` module invoked from the `inner-tunnel` virtual server's
`authorize {}` section, and:

1. Splits the inner `User-Password` into `<base_password><6-digit-otp>`
2. Validates `base_password` against Asgardeo via ROPC
3. Fetches the user's Asgardeo groups via the `userinfo` endpoint
4. Validates the TOTP code locally (`otp_check.py`) against a per-user
   enrolled secret, with a ±30s drift window, replay protection, and
   failure rate-limiting
5. Maps the user's Asgardeo group to a FortiGate group name
   (`vpn_group_map.yaml`) and sets `Fortinet-Group-Name` on accept
