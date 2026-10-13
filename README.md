# Keycloak Impersonation Flow using Action Tokens

A Keycloak SPI extension that replaces the default "impersonate now, set a cookie" admin flow with a
link-based one. The admin endpoint returns a short-lived, signed link; impersonation happens only when
that link is opened in a browser.

## Problem

Keycloak's built-in impersonation endpoint sets the `KEYCLOAK_IDENTITY` and `KEYCLOAK_SESSION` cookies
directly on the response, in the same request the admin console makes. This breaks when the admin console
and the realm it manages are on different hostnames (e.g. `admin.example.com` vs. `auth.example.com`):
the cookies are set for the admin hostname, then dropped as third-party cookies once the browser is
redirected to the realm hostname. The admin ends up on the account page, not logged in as anyone.

Tracked upstream as [keycloak/keycloak#10655](https://github.com/keycloak/keycloak/issues/10655) since
March 2022. It also makes impersonation awkward to drive from anything other than the admin console UI
(a backend service, a script), since the default endpoint assumes the caller is a browser holding onto
cookies.

## How this fixes it

Instead of setting cookies immediately, the admin endpoint creates a signed, single-use **action token**
(Keycloak's existing mechanism for email verification and password reset links) and returns it wrapped
in a URL. Nothing is impersonated yet — the response is just a link.

Impersonation happens when the link is opened, because it hits Keycloak's action-token processor on the
realm's own hostname, not the admin hostname. Cookies get set where they're needed, so there's no
cross-domain cookie to lose. This also makes the endpoint easier to call from non-browser clients: the
caller just needs to hand the returned link to a browser eventually.

The same approach is proposed for Keycloak core in
[keycloak/keycloak#40767](https://github.com/keycloak/keycloak/pull/40767), which patches the endpoint
into `UserResource` directly. This repo implements it as a standalone SPI extension instead: a jar
dropped into `providers/`, no Keycloak fork required. The trade-off is that it can't replace the
built-in endpoint's URL (Keycloak doesn't allow overriding a core resource), so it's exposed at a
different path — see [Routing around the built-in endpoint](#routing-around-the-built-in-endpoint).

## Trade-offs and limitations

- The link expires in 180 seconds (hardcoded, not configurable).
- The link is single-use. A second visit returns "Action token already used" instead of impersonating
  again — call the admin endpoint again for a new link.
- The link only works opened in a browser; it isn't something a backend service can follow itself to
  obtain a session.
- It can't live at the same URL as the built-in endpoint, since this is a bolt-on SPI rather than a
  patch to Keycloak core. To make the stock admin console use it transparently, requests need to be
  rewritten in front of Keycloak — see below.
- `sameRealm` in the response is currently always `false`, regardless of whether the impersonation is
  same-realm or cross-realm.

### Routing around the built-in endpoint

The admin console UI calls the built-in impersonation endpoint at a fixed path:
`/admin/realms/{realm}/users/{user-id}/impersonation`. This extension can't take over that path, so it
registers at `/admin/realms/{realm}/impersonation/users/{user-id}` instead.

To make the stock admin console use this extension without modifying its frontend, put a reverse proxy
in front of Keycloak that rewrites the built-in path to the extension's path. This repo's
[`nginx.conf`](./nginx.conf) does that, keyed on a separate `keycloak-admin.localhost` hostname so only
admin-console traffic gets rewritten.

Equivalent rewrites for other reverse proxies:

**nginx**

```nginx
rewrite ^/admin/realms/(.*)/users/(.*)/impersonation$ /admin/realms/$1/impersonation/users/$2 last;
```

**Traefik** (dynamic config)

```yaml
http:
  middlewares:
    impersonation-rewrite:
      replacePathRegex:
        regex: "^/admin/realms/([^/]+)/users/([^/]+)/impersonation$"
        replacement: "/admin/realms/$1/impersonation/users/$2"
```

**Caddy**

```
@impersonate path_regexp impersonate ^/admin/realms/([^/]+)/users/([^/]+)/impersonation$
rewrite @impersonate /admin/realms/{re.impersonate.1}/impersonation/users/{re.impersonate.2}
```

**HAProxy**

```
acl is_impersonate path_reg ^/admin/realms/[^/]+/users/[^/]+/impersonation$
http-request set-path %[path,regsub(^/admin/realms/([^/]+)/users/([^/]+)/impersonation$,/admin/realms/\1/impersonation/users/\2)] if is_impersonate
```

## Installation

```sh
# Build the SPI jar for Keycloak 26.7.x and newer
./mvnw clean package

# ... or for Keycloak 26.6.x
./mvnw clean package -Pkeycloak-26.6
```

| Build                 | Jar                                                                     | Keycloak            |
|-----------------------|-------------------------------------------------------------------------|---------------------|
| default               | `target/twobiers.keycloak-keycloak-impersonation-action-token.jar`      | 26.7.x and newer    |
| `-Pkeycloak-26.6`     | `target/twobiers.keycloak-keycloak-impersonation-action-token-26.6.jar` | 26.6.x              |

Drop the jar matching your Keycloak version into the instance's `providers/` directory (typically
`/opt/keycloak/providers/`) and restart, or rebuild the Keycloak container image with it included.

Two jars are required because Keycloak 26.7 replaced the single-use-object `.revoked` convention with the
dedicated `RevokedTokenProvider` (`KeycloakSession#revokedTokens()`, added in 26.7) and
`LoginActionsServiceChecks#checkTokenWasNotUsedYet` now only consults the new store. 26.6 has no such
provider, so it still revokes by inserting the serialized action token key plus `.revoked` into the
single-use object store. Since neither revocation call exists on the other line, the revocation helper is
the one line-specific piece of code (`src/main/java-kc26.7` and `src/main/java-kc26.6`, selected by the
`keycloak.line.dir` property); everything else is shared. Because neither revocation call exists on the
other line, no single jar can be loaded by both lines.

The integration tests run against a real Keycloak image, which can be pinned/overridden with
`-Dkeycloak.image=quay.io/keycloak/keycloak:<version>` (the `keycloak-26.6` profile pins it to 26.6.4,
the default build uses `nightly`).

To try it locally, `docker compose up` starts Keycloak with the jar mounted, fronted by an nginx
container that performs the path rewrite described above. It expects `keycloak.localhost` and
`keycloak-admin.localhost` to resolve to `127.0.0.1` (add them to `/etc/hosts`), and bootstraps an
`admin`/`admin` account. The admin console is then at `http://keycloak-admin.localhost:8080`.

## API reference

### `POST /admin/realms/{realm}/impersonation/users/{user-id}`

Requests an impersonation link for the given user. Requires a bearer token for a caller with
impersonate permission on that user (the standard Keycloak admin fine-grained-permission check applies).

**Path parameters**

| Parameter | Description                                          |
|-----------|------------------------------------------------------|
| `realm`   | Name of the realm the target user belongs to         |
| `user-id` | ID of the user to generate an impersonation link for |

**Response — `200 OK`**

```json
{
  "sameRealm": false,
  "redirect": "https://your-keycloak-host/realms/{realm}/login-actions/action-token?key=..."
}
```

| Field       | Type    | Description                                                                              |
|-------------|---------|------------------------------------------------------------------------------------------|
| `sameRealm` | boolean | Currently always `false` — see [Trade-offs and limitations](#trade-offs-and-limitations) |
| `redirect`  | string  | The impersonation link. Open it in a browser to complete the impersonation.              |

**Error responses**

| Status            | Condition                                                                                   |
|-------------------|---------------------------------------------------------------------------------------------|
| `404 Not Found`   | No user with the given `user-id` exists in the realm                                        |
| `400 Bad Request` | User is disabled, or the user is a service account (service accounts can't be impersonated) |
| `403 Forbidden`   | Caller doesn't have impersonate permission for the target user                              |

### The `impersonate` action token

The link returned above encodes a signed action token of type `impersonate`. It's meant to be opened in
a browser, not consumed as an API — but its fields and behavior are useful when auditing the flow.

| Field                 | JSON key            | Description                                            |
|-----------------------|---------------------|--------------------------------------------------------|
| target user ID        | *(inherited)*       | The user who will be impersonated                      |
| impersonator username | `impersonator`      | Username of the admin who requested the impersonation  |
| impersonator ID       | `impersonatorId`    | ID of the admin who requested the impersonation        |
| impersonator realm    | `impersonatorRealm` | Realm the impersonating admin belongs to               |
| redirect URI          | `reduri`            | Where to send the browser once impersonation completes |

**Expiry:** 180 seconds from creation, matching the endpoint above.

**Single use:** the token is invalidated the moment it's handled, before any impersonation logic runs.
Unlike most action tokens, which stay valid until their linked required action is completed, this one has
no required action step, so it invalidates itself immediately to prevent replay.

**What happens when the link is opened:**

1. The target user is re-validated (exists, enabled, not a service account) — the same checks the admin
   endpoint already made.
2. If the browser has an active impersonation session for a different user, that session is torn down
   first (identity, remember-me, and auth-session cookies expired, backchannel logout triggered), so
   only one impersonation is active at a time.
3. A new user session is created for the target user, tagged with the impersonator's ID and username.
4. An `IMPERSONATE` audit event is recorded, including the impersonator's realm and username.
5. The browser is redirected to `reduri` from the token, now logged in as the impersonated user.
