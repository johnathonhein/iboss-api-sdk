# Proxy & Caching

**Console:** Network → Proxy & Caching ·
**Tier:** gateway (`/json/...`) · **SDK:** `client.network`

Proxy settings (ports, modes, timeouts, file scan limits) and proxy logging
toggles.

| Endpoint | SDK method |
|---|---|
| `POST /json/network/proxy/settings` | `updateProxySettings(settings)` |
| `POST /json/preferences/reportSettings/changeProxyLogging` | `updateProxyLogging({ logProxyAccessDeniedErrors, logProxyAllOtherErrors, logProxyDnsConnectionFailures })` |
| `GET /json/network/proxy/acl/rule?entryType=2` | `listProxyAclRules(entryType?)` |
| `POST /json/network/proxy/acl/rule/position?id=&toId=` | `moveProxyAclRule({ id, toId })` |

`moveProxyAclRule` re-GETs rule order after the position POST. Gateway can return success while the order is unchanged (DEVELOP-34959). The SDK throws `IbossVerifyError` on that silent no-op and does not trust the POST `moved` flag. When the position body includes `orderRevision` / `resultingIndex`, those fields are copied onto the result; otherwise `orderRevision` stays `null`.

`beforeRuleId` / `afterRuleId` are client-side aliases resolved to `toId`. They are not sent. A dropped connection re-GETs before any second POST — the position call is not idempotent, so the request layer does not retry it on its own. `id` and `toId` are absolute ACL-map indices from the entryType=2 list.

Notes:

- Settings objects are full-echo: read the current settings first
  (`client.raw("gateway", "GET", "/json/network/proxy/settings")`), modify,
  POST the whole object back.
- SSL/TLS decryption settings live under Network → SSL Decryption — see
  [ssl-decryption.md](ssl-decryption.md).
- ZTNA Private Access settings (routed peers, DHCP gateway/NAT) are covered
  in [private-access-policies.md](private-access-policies.md); connector
  general settings (security keys) in
  [connector-policies.md](connector-policies.md).
