# Resource Policies (SaaS & Internet Access Policies)

**Console:** Secure Access Policies → SaaS & Internet Access Policies ·
**Tier:** gateway (`/json/...`) · **SDK:** `client.policies`

Resource Policies control access to internet and SaaS destinations: default
internet access, restricted categories, global blocklists/allowlists,
approved apps, and CASB controls. They are the policies you see as numbered
rows in the SaaS & Internet Access Policies screen, and they can be
associated with [Resources](resources.md) from the catalog.

On the wire, a Resource Policy is a policy object with
**`isZeroTrustResourcePolicy: 1`** and a mandatory **`dlpPolicyMethod: 2`**
in its settings payload. (Overlay [Policy Layers](policy-layers.md) share the
same endpoints but have `isZeroTrustResourcePolicy: 0`.)

## Creation is two-step

1. **Create structure** — `PUT /json/controls/policyLayers`

   ```json
   {
     "customCategoryName": "Approved Apps",
     "customType": "e_custom_category_type_allowlist",
     "isZtnaPrivateAccessCategory": 0,
     "isZeroTrustResourcePolicy": 1,
     "enterpriseOwned": 0,
     "policyEnabled": 1,
     "placeAtPosition": 0
   }
   ```
   → `{ customCategoryId, customCategoryNumber, id, successful }`

2. **Apply settings** — `POST /json/controls/policyLayers/settings` with the
   ids from step 1, **`dlpPolicyMethod: 2`**, `policyAction` (1=allow,
   0=block), `linkPolicyToAllSubjects`, and the generated field families
   (`cat0..cat110`, `prio0..prio110`, `bypassSslMitm0..bypassSslMitm110`,
   400-char `categories` bitmap).

`client.policies.createLayer({ isZeroTrustResourcePolicy: 1, ... })` performs
both steps and injects `dlpPolicyMethod: 2` and the field families for you.
It returns the ids from step 1.

## Agent update (DEVELOP-34914)

SDK-only. This repo does not change Gateway / lockboxLinux, and this helper
does not call an HTTP PATCH. Native Gateway merge is
[DEVELOP-34921](https://ibosscybersecurity.atlassian.net/browse/DEVELOP-34921)
and is out of scope.

`patchResourcePolicySettings` uses the settings paths this SDK already uses:

```
GET  /json/controls/policyLayers/settings?customCategoryId=…
POST /json/controls/policyLayers/settings    body = deep-merge(GET, patch)
```

Gateway POST applies defaults for omitted fields (same class as
[DEVELOP-34251](https://ibosscybersecurity.atlassian.net/browse/DEVELOP-34251)
and [DEVELOP-32482](https://ibosscybersecurity.atlassian.net/browse/DEVELOP-32482)).
A sparse body can reset `catN` / `prioN` / `bypassSslMitmN` to those defaults
and drop unrelated prior fields. The helper deep-merges the caller patch onto
the full GET blob, fills only family members the GET lacked, and POSTs that
complete object. Omitted patch keys keep prior values.

The helper then GETs again and returns that blob. `IbossVerifyError` means
the POST returned success (including an empty `saveIgnoredEntries`) but a
**patch field** — or `dlpPolicyMethod` when the helper had to fill it — is
not in the follow-up GET. Family members are sent in the full body; the
returned object is the confirming GET, so a family value that did not
round-trip is visible on that object.

**TOCTOU / concurrent writers (accepted for agent v1).** Another client can
write the same policy between the GET and the POST. Last POST wins. There
is no ETag or lock on this path.

```ts
const policy = await client.policies.createResourcePolicy({
  name: "Approved Apps",
  type: "allowlist",
  settings: { policyAction: 1, linkPolicyToAllSubjects: 1 },
});
// `policy` is the effective GET settings blob, not only the new ids.

await client.policies.patchResourcePolicySettings(Number(policy.customCategoryId), {
  aiRiskEnabled: 1,
});

const full = await client.policies.getResourcePolicySettings(Number(policy.customCategoryId));
```

| Method | What it does |
|---|---|
| `getResourcePolicySettings(id, { view? })` | Dedicated read of `GET /json/controls/policyLayers/settings`. Default `view` is `full` (the wire blob). `summary` omits the bitmap and catN families. |
| `patchResourcePolicySettings(id, patch)` | GET → deep-merge → full POST of the same settings path, then a confirming GET. Omitted keys keep prior values, including every catN / prioN / bypassSslMitmN. TOCTOU is accepted for agent v1. |
| `createResourcePolicy({ name, type, settings? })` | `createLayer({ isZeroTrustResourcePolicy: 1, ... })` plus a GET of the settings that were stored. Returns that effective object. |
| `updateLayerSettings(fullBlob)` | Unchanged caller-supplied POST. A sparse body is sent as-is and can wipe omitted fields. |

## Endpoints

| Endpoint | SDK method |
|---|---|
| `GET /json/controls/resourcePolicies` | `listResourcePolicies()` |
| `GET /json/controls/policyLayers/all?isZeroTrustLayer=1&...` | `listLayers({ isZeroTrustLayer: 1 })` |
| create (two-step, returns ids) | `createLayer({ isZeroTrustResourcePolicy: 1, ... })` |
| create + GET effective settings | `createResourcePolicy({ name, type, settings? })` |
| `GET /json/controls/policyLayers/settings?customCategoryId=` | `getLayerSettings(id)` / `getResourcePolicySettings(id)` |
| `POST /json/controls/policyLayers/settings` | `updateLayerSettings(...)` (full replace) / `patchResourcePolicySettings(id, patch)` (get-merge-post) |
| `DELETE /json/controls/policyLayers?customCategoryId=` | `deleteLayer(id)` |
| `GET /json/controls/resourcePolicy/resources?customCategoryId=` | `getResourcePolicyResources(id)` |
| `PUT /json/controls/resourcePolicy/resources?customCategoryId=` | `associateResources({ customCategoryId, customCategoryNumber, resourceIds })` |

## Associating Resources

Resource Policies act on entries from the [Resource catalog](resources.md).
Associate the **enterprise-owned** copy of a resource:

```ts
const policy = await client.policies.createLayer({
  name: "Approved Apps",
  type: "allowlist",
  isZeroTrustResourcePolicy: 1,
  settings: { policyAction: 1, linkPolicyToAllSubjects: 1 },
});

const resource = await client.resources.getByName("Example SaaS App");
await client.policies.associateResources({
  customCategoryId: policy.customCategoryId,
  customCategoryNumber: policy.customCategoryNumber,
  resourceIds: [resource!.uuid],
});
```

Gotchas:

- Association is a **PUT** with `customCategoryId` as a query param and the
  body field named **`resourceIds`** — both ids are required.
- `dlpPolicyMethod: 2` is mandatory in every Resource Policy settings
  payload; omitting it produces broken policies.
- **No native Gateway PATCH.** `patchResourcePolicySettings` is GET →
  deep-merge → full POST. A concurrent writer between that GET and POST
  wins the last write. That TOCTOU window is accepted for agent v1.
- CASB-control policies are allowlist-type Resource Policies with
  `enterpriseOwned: 1`.
- Group-targeted policies: `linkPolicyToAllSubjects: 0` +
  `associatedGroups: "2,3"` + `enableGroupAssociation: 1` in settings
  (group numbers from [default-policy-groups.md](default-policy-groups.md)).
