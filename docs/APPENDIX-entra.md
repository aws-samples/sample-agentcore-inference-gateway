# Appendix — using Microsoft Entra ID instead of Cognito

This repo ships with **Cognito** as the identity provider, because it makes the demonstration
self-contained: CDK provisions the IdP, so anyone can clone, deploy and run the walkthrough
with no external tenant.

Many enterprises run **Microsoft Entra ID** instead. The gateway's `CUSTOM_JWT` authorizer
works with either, and this appendix is the guide to the swap: what configuration changes,
what breaks if you miss a step, and how the client login differs. It is written as "what to do
if you use Entra", not as a changelog — the Cognito path remains the default in code.

---

## 1. Point the gateway authorizer at Entra

The `CUSTOM_JWT` authorizer takes an OIDC discovery URL and an audience. For an Entra tenant:

| Setting | Value |
|---|---|
| Discovery URL | `https://login.microsoftonline.com/<TENANT_ID>/v2.0/.well-known/openid-configuration` |
| Issuer | `https://login.microsoftonline.com/<TENANT_ID>/v2.0` |
| Audience | both `api://<CLIENT_ID>` **and** the bare `<CLIENT_ID>` |
| Scope | `api://<CLIENT_ID>/inference.invoke` |
| Client type | public client + PKCE (no secret) |
| Redirect URI | `http://localhost:8400/callback` (registered under *Mobile and desktop applications*) |

Entra-specific things that will bite you if you skip them:

- **Set `requestedAccessTokenVersion: 2` in the app manifest.** Otherwise Entra issues v1
  tokens whose issuer is `https://sts.windows.net/<tenant>/`, which does **not** match the v2
  discovery document the gateway fetches — you get a confusing `invalid_token`.
- **A v2 access token sets `aud` to the bare client id**, not the `api://…` URI. Accept both
  forms or v2 tokens are rejected.
- **Group claims may be GUIDs, not names.** On the tenant tested here the `groups` claim carried
  group **object ids**, so the Cedar policy has to match GUIDs. Check this per tenant — it
  changes how you write the policy.
- **Watch for the groups overage claim.** For a user in many groups, Entra replaces the inline
  `groups` claim with `_claim_names` / `_claim_sources`, and the list must be fetched from
  Microsoft Graph instead. Any policy keyed on `groups` silently stops matching.

## 2. What changes relative to the Cognito path

| | Entra | Cognito (default here) |
|---|---|---|
| Audience validation | `allowed_audience` (both token forms) | **`allowed_clients` only** — access tokens have no `aud` |
| Group claim | `groups` (often GUIDs) | `cognito:groups` (names) |
| Custom claims | app roles / optional claims | **none needed** — governance reads `cognito:groups` and resolves everything else from the config table |
| Notebook login | interactive browser PKCE | non-interactive `USER_PASSWORD_AUTH` |
| Self-contained | no — needs a tenant you administer | yes — created by CDK |

The last row is why Cognito is the default: a self-contained clone-and-run demo matters more
here than matching a specific enterprise IdP, and the browser PKCE flow makes an unattended
notebook walkthrough awkward. Neither identity axis needs a custom claim — governance keys on
group membership and reads the rest from the config table, so a `tier`-style scalar claim (which
on Cognito would force a pre-token-generation Lambda and the `ESSENTIALS` feature plan) is not
required on either provider. The reasoning behind dropping that second axis is in
[`FINDINGS.md`](FINDINGS.md).

**To actually switch**, you re-add the Entra authorizer configuration above; the code no longer
carries it. `pilot/config.py` has no `EntraConfig`, no tenant/client GUIDs and no Entra group
ids, and `msal` is not in `requirements.txt` — only a comment pointing here remains, and no
GUID-shaped identifiers survive anywhere under `pilot/`.

## 3. Client login differs too

The Cognito path logs in non-interactively with `USER_PASSWORD_AUTH` (`ic.get_token(user,
password)`), needs no browser and no token cache, and is what `pilot/inference_client.py` and
the notebook use. An Entra public-client + PKCE flow is interactive: the user authenticates in a
browser once, and a refresh token keeps subsequent runs silent until it expires. Any client that
accepts **a base URL plus a bearer token** works against the gateway regardless of which IdP
minted the token — `curl`, the OpenAI SDK, the Anthropic SDK, the notebook client. Note that
boto3 `invoke_model` is **not** the path: the gateway exposes an LLM-provider REST API, not the
Bedrock control API.

### ⚠️ Claude Code cannot be pointed at the gateway (either IdP)

Worth calling out because it is a natural thing to try: Claude Code sends both an
`authorization` header and an `x-api-key` header on every request, and the gateway rejects
requests carrying both —

```
401  request must not include both
```

There is no Claude Code setting that suppresses one of the two headers, so it cannot target an
AgentCore Gateway inference target directly, on Entra or Cognito. Use Claude Apps Gateway for
that client instead. This is a deliberate non-goal, not an open bug.

---

*Earlier iterations of this pilot shipped standalone client tooling for the Entra path — an MSAL
PKCE token helper (Python and PowerShell), a request driver for the validation runs, a Claude
Code settings attempt, and an EC2 sandbox to host the interactive browser login. All of it was
removed once `pilot/inference_client.py` and the notebook made a browser and a sandbox
unnecessary; the durable lessons (the Entra token quirks above, and the Claude Code dual-header
limitation) are captured in this appendix.*
