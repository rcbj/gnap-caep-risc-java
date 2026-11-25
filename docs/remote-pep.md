# Using the iya-sts Remote PEP

This library can ask iya-sts's authorization policy whether the person a GNAP grant names (a `Person`, or the `Grant` itself) may do something to a resource in your application, through an embedded **Remote PEP** (Policy Enforcement Point). The PEP itself is [`com.iyasec:iya-pep`](https://github.com/rcbj/iya-pep-java) 0.1.0. This library builds it from your configuration (`com.iyasec.gnap.EmbeddedPep`), turns a GNAP sign-in into the PEP's subject, and hands it policy-change events from its Shared Signals stream. The design is [iya-sts #1206](https://github.com/rcbj/iya-sts/issues/1206).

The PEP never permits by default. A decision is a Permit, a Deny or Unavailable, and Unavailable (no policy held yet, iya-sts unreachable, or a failure while deciding, which the PEP catches) is a refusal. `decision.httpStatus()` is 200 for a Permit and 403 for a Deny and for Unavailable alike. Whether the person is signed in at all (401) is your application's question, asked before the PEP's.

`decide` and `decideGrant` do not throw. A failure is an Unavailable decision.

## Choosing a mode

| | `central` | `local` |
|---|---|---|
| Who decides | iya-sts, per request (`POST /access/v1/evaluation`) | this process, with the PEP's own XACML engine |
| Dependency | `com.iyasec:iya-pep` (always on the classpath; there is no feature flag) | the same jar. `local` is the default mode |
| Latency | one HTTPS round trip per decision | none after the first pull |
| When iya-sts is down | every decision is Unavailable, and any cached Permit is dropped | decisions continue with the policies held |
| Policy changes | at once | on the `pep-policies-changed` event, or the next poll |
| Decision records | written by iya-sts | sent by the PEP to iya-sts's audit log |

Pick `central` when decisions are infrequent or must reflect a change immediately, and `local` when decisions are on a hot path or must survive a short outage. Both modes are meant to give the same answer for the same request: `local` maps the request through the realm's catalogue exactly as iya-sts does. The engine's conformance corpus lives in `iya-pep`. This library does not ship that table.

## Before you start: set up iya-sts

You need an iya-sts release with embedded-PEP support (iya-sts #2026, #2027 and #2028). The steps below use the management API; `$API` is `https://<host>/realm/<realm>/admin-api` (or `https://<host>/admin-api` for the default realm) and `$TOKEN` a token for it with write access. Every step has a console equivalent, named after it. `scripts/configure_iya_sts.py --pep` does steps 2 to 6 for the demo (a bare `--pep` is `local`).

```bash
api() { curl -s -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d "$2" "$API/$1"; }
```

### 1. Register the application

Register the GNAP client in iya-sts as usual; `scripts/configure_iya_sts.py` does it for the demo. Note its identifier: it is the `application` the PEP is bound to (the configuration's own `application` by default). The install script writes `gnapKey` when it creates the application. A later run leaves `gnapKey` as it is. It does not call `issue-tls-client-certificate`. The mTLS certificate is the client instance key.

### 2. Create the PEP's service account

The PEP signs in as a service account of its own, never as a person or as the application. The demo's account is `pep-gnap-demo` (`--pep-name`):

```bash
api users/create '{"username":"pep-orders","invent":false,
  "credential":"none","serviceAccount":true,"owners":["admin-write"],
  "attributes":{"cn":"pep-orders","displayName":"pep-orders"}}'
api groups/add-member '{"group":"remote-peps","member":"pep-orders"}'
```

The install script creates the account only when `/users?user=` says it is unknown, and always adds it to `remote-peps`.

Console: **Users → New user** (tick **Service account**), then the `remote-peps` group's **Add member**.

### 3. Make the PEP's key, certify it and bind the PEP

Generate the key where the application runs. Only the certificate request leaves the machine:

```bash
openssl ecparam -name prime256v1 -genkey -noout | \
  openssl pkcs8 -topk8 -nocrypt -out pep-key.pem
openssl req -new -key pep-key.pem -subj /CN=pep-orders -out pep-key.csr
api xacml/issue-pep-credential "$(jq -n --rawfile csr pep-key.csr \
  '{name: "pep-orders", csr: $csr, application: "<application id>"}')"
```

`application` binds the PEP to the application in the same call (`POST /admin-api/xacml/set-pep-application` does it on its own). An EC P-256 key is preferred; RSA of 2048 bits or more is accepted. **The key must be the PEP's own.** This library holds one key, the client instance key, and the mTLS certificate is that same key. It refuses a configuration whose JWK thumbprints match: `pep.assertionKey is the GNAP client instance key (privateKey); the PEP needs a key of its own`.

The install script writes `generated/pep-key.pem` mode 0600 with `openssl`, never prints the key, and calls `issue-pep-credential` when the key or the account is new. Otherwise it calls `set-pep-application`. `.dockerignore` keeps `demo/generated/*` out of the image except `idp-ca.pem`.

Console: **Protocols → XACML → Remote PEPs**, **Certify the key**, then the PEP's Overview, **Embedded in an application**.

### 4. Declare the claims your policy reads

The PEP sends a subject's claims only through the realm's AuthZEN attribute catalogue: a claim with no catalogue row is not sent (iya-sts would refuse the whole request). Add one row per claim your policy uses, on **Protocols → XACML → AuthZEN** or with `POST /admin-api/xacml/authzen/set-attribute`. The demo's row, and the row every sibling demo shares, is exactly:

```bash
api xacml/authzen/set-attribute '{"object":"subject","property":"acr","attributeId":"urn:example:acr"}'
```

| `object` | `property` | `attributeId` |
|---|---|---|
| `subject` | `acr` | `urn:example:acr` |

The same applies to `resource.properties`, `action.properties` and `context` members you put on an `Access`. The demo's directory attribute `attr1` uses `urn:sts:xacml:attribute:attr1`. iya-sts's [AuthZEN page](https://rcbj.github.io/iya-sts/v1.2.0/authzen.html), *The realm's conversion rules*, describes the rows.

### 5. Write the policy

The policy that decides is the application's own fine-grained authorization policy when the application enforces fine-grained authorization, and otherwise the realm's root policy. A `local` PEP is sent that policy and everything it references, and nothing else. The subject's id arrives as XACML's `subject-id`, the action's name as `action-id` and the resource's id as `resource-id`. The resource's type arrives as `urn:sts:xacml:authzen:resource-type`.

The demo writes an ALFA policy onto the application's own policy and enforces it. PolicyId `urn:example:gnapdemo-orders`. It does not call `xacml/set-root`. While that PolicyId is the one enforced, a later run writes the current text. A policy under any other PolicyId is left as it is. `read` on an `order` is permitted when `acr` arrived. `read` on `attribute-protected` is permitted when `attr1` is `abc123`. Anything else, including `write` on an order, is denied.

### 6. (`local` with signals) let the event through

If the application's entry restricts its Shared Signals streams with `ssfAllowedEvents`, add `urn:iya:sts:secevent:event-type:pep-policies-changed` to it. Otherwise the PEP doesn't hear of a change until its fallback poll. The install script adds the event only when that list is already non-empty and does not contain it.

## Credentials

The application's own credentials (the client instance key and the GNAP tokens), the install-time admin secret, the trust material and the development and product notes are in the README's [Credentials](../README.md#credentials). The PEP's are these:

- **Identity.** The PEP is a service account of its own (step 2): no password (`credential: none`), in `remote-peps`, bound to one application. It is never a person, and never the application.
- **The PEP key** (`pep.assertionKey`, relative to the configuration's directory):
  - **Type.** EC P-256, or RSA of 2048 bits or more.
  - **Made where it runs.** Only its certificate request leaves the machine (step 3). The demo's install script writes `generated/pep-key.pem` 0600 with `openssl`, never prints it, and `.dockerignore` keeps it out of the image.
  - **Registered by `issue-pep-credential`.** That call certifies the request, registers the key for the PEP's entry, and binds the PEP to the application. A kept key and a kept account use `set-pep-application`.
- **What the key authenticates.** Each call the PEP makes starts from an RFC 7523 JWT assertion, signed with this key (`iss` and `sub` are the PEP's `name`), sent to the realm's token endpoint as client `clientId` (default `sts-remote-pep`). The answer is a DPoP-bound (RFC 9449) access token, and every call carries a DPoP proof signed with the same key. Audiences are `xacml:pep` (registration, heartbeat, catalogue, policies, `POST /xacml/pip`), `xacml:pep-audit` (decision records) and `authzen:evaluate` (`central` evaluations). Tokens are renewed before they expire and are never logged. Without a token the call is not made, and a decision that needed it is Unavailable (a 403).
- **It must not be the client instance key.** The library compares JWK thumbprints after `Pep.create` and refuses when both are non-empty and equal. The client instance key proves the application's GNAP requests, including mutual TLS, and holds its grants. The PEP key proves a different principal.
- **Rotation.** Make a new key, have it certified with `issue-pep-credential`, and replace the file. The PEP reads the file again when it changes. For the demo, delete `demo/generated/pep-key.pem` and run `configure_iya_sts.py --pep` again.
- **Trust.** The PEP verifies iya-sts with `pep.tlsCa`, by default the library's `tlsCa` when that value contains a PEM block.

## Build with the feature

This library has no Cargo-style feature and no build flag that turns the PEP off. `library/pom.xml` depends on `com.iyasec:iya-pep:0.1.0`. The local engine is in that jar, so a section that names no `mode` is `local`. A `pep` section is ignored only when it is absent.

Until `iya-pep` is on Maven Central, this work stays on `develop`. A merge to `main` publishes `gnap-caep-risc`, and that publish cannot depend on a git pin. The image clones `https://github.com/rcbj/iya-pep-java.git` branch `develop` and runs `mvn -B -DskipTests install` before `mvn -B test` and before `mvn -B -DskipTests package`. A clone that fails because `develop` is not pushed is left failed. Do not run Maven on the host. Bytecode is 17. The test image is `maven:3.9-eclipse-temurin-26`. The demo runtime image is `eclipse-temurin:25-jre`.

## Configure

Add a `pep` section to `gnap.json`. The PEP is off unless it is present.

```json
"pep": {
  "name": "pep-orders",
  "mode": "local",
  "assertionKey": "pep-key.pem"
}
```

| Member | Default here | What it is |
|---|---|---|
| `name` | required | The PEP's service account (step 2). |
| `mode` | `local` | `local` (the PEP pulls its application's policies, caches them in memory and decides in process) or `central` (it asks iya-sts for every decision). |
| `assertionKey` | required | The PEP's private key in PEM. A relative path is resolved against the configuration directory and made absolute before `PepConfig.fromJson`, like `privateKey`. The PEP reads the file, and again when it changes. |
| `pdpUrl` | the grant endpoint's realm. `https://sts.example/realm/acme/gnap` and `https://sts.example/realm/acme/as/gnap` both give `https://sts.example/realm/acme`. `https://sts.example/gnap` gives `https://sts.example`. An unparseable URL gives `""` | iya-sts, with `/realm/<id>` kept. A named server's segment and `/gnap` are dropped. Otherwise the origin. `idTokenIssuer` is not the default: it is the origin and drops the realm. |
| `application` | the configuration's `application` | The application the PEP is bound to (step 3). |
| `clientId` | `sts-remote-pep` | The client the PEP's assertion is presented through. |
| `signals` | on when this library runs a receiver (signals on and a transmitter configured) | Whether a signal stream hands over policy-change events. Without one, `local` polls at `pollIntervalMs`. |
| `pollIntervalMs` | 15000 | `local` without a signal stream. |
| `fallbackPollMs` | 300000 | `local` with one, in case an event is lost. |
| `heartbeatIntervalMs` | 30000 | How often the PEP reports to iya-sts. |
| `permitCacheMs` | 0 (off) | `central` only: reuse a Permit for this long, at most 60000. The policy-change event clears it, and so does a failed evaluation or a failed heartbeat. |
| `supportedObligations` | `[]` | The obligation types your application discharges (see *Obligations*). |
| `decisionRecords` | `true` | `local`: send each decision to iya-sts's audit log. |
| `tlsCa` | the library's `tlsCa`, when that value contains a PEM block | PEM trust anchors for iya-sts's TLS. |
| `timeoutMs` | 10000 | Per request to iya-sts. |

An unknown member is refused by `PepConfig.fromJson`, so a misspelt one does not fall back to a default. `GnapClient.fromFile` and `GnapClient.create` start the PEP. `GnapClient.resolve` and `Config.readFile` build it and do not start it.

## Decide

```java
import com.iyasec.gnap.GnapClient;
import com.iyasec.pep.Access;
import com.iyasec.pep.Decision;

GnapClient gnap = GnapClient.fromFile("gnap.json"); // starts the PEP; local mode pulls

// After the grant is approved (and ensureFresh if the token may have expired):
Access access = Access.of("read", "order", orderId);
Decision decision = gnap.decideGrant(grant, access);
int status = decision.httpStatus(); // 200 for a Permit, 403 for anything else
if (status == 200) {
    serve();
} else {
    forbidden(status, decision.why()); // Deny or Unavailable: fail closed
}
// For a Person you hold yourself: gnap.decide(person, access)
```

`Access.of(action, resourceType, resourceId)` carries the AuthZEN action and resource. Add resource properties, action properties or context members as your policy needs them, each declared in the catalogue (step 4). The PEP sets `context.application` to the bound application.

**The subject** comes from the sign-in, never from a request header (`EmbeddedPep.subjectFor`):

- **id:** `uid` from the grant's `account` subject identifier (`acct:user@host` yields `user`), else the assertion's `username` claim, else `preferred_username`, else `sub`. Empty values are skipped until `sub`, which is kept even when empty. `sub` can be pairwise, so it is the last resort.
- **properties:** a copy of the verified ID token claims. This library's `Person` keeps `acr` and `amr` in that claim map.

Only the properties the catalogue declares are sent.

**Ended grants.** `decideGrant` is a Deny without asking when the grant has ended: it has no subject (`the grant names no subject`), this client revoked it (`the grant was revoked`; the newest 10,000 continuation URIs, recorded by `revoke`), or its access token has expired (`the grant's access token has expired`; `expiresAt` at or before now). Rotate it with `ensureFresh` first.

**Without a `pep` section**, every decision is Unavailable (`no pep section is configured`). `httpStatus()` is still 403.

### Obligations

A Permit can carry obligations, which your application must carry out before it grants the access (for example a `step-up` to a stronger `acr`). The PEP only hands you obligations of types you list in `supportedObligations`. A Permit carrying any other obligation is turned into a Deny, so an obligation is never silently dropped. Advice can be ignored. `central` carries it only while the realm's `authzen.returnReasons` is on.

```json
"pep": { "name": "pep-orders", "assertionKey": "pep-key.pem", "supportedObligations": ["step-up"] }
```

## Receive policy-change events

In `local` mode, and in `central` mode with a Permit cache (`EmbeddedPep.wantsEvents`), the PEP wants to hear when the policies change. Give the receiver the PEP before `start`:

```java
receiver.setAddSubjects(gnap.config().addSubjects);
receiver.usePep(gnap.pep());
receiver.start();
```

`usePep` asks the stream for `Pep.POLICIES_CHANGED_EVENT` (`urn:iya:sts:secevent:event-type:pep-policies-changed`), verifies each SET like every other one, and hands the event body to `onPolicyEvent`. A stream that already exists is updated with PATCH to ask for the types it lacks, when `events_requested` is an array. If the transmitter refuses, the receiver still starts, the refusal goes to `setOnError` (standard output without one), and the PEP is told the event is excluded. The event is only a hint: the PEP pulls with its own credential.

The receiver tells the PEP how its stream is doing, which the heartbeat reports and the PEP's own policy poll follows: `requested` or `excluded` at `start` and after every good poll, `down` after a failed poll and on `stop()`. While it is `down` the PEP polls its policies itself. `stop()` does not wait until the poll thread has finished.

The receiver also adds each signed-in person (Add Subject at sign-in, Remove Subject after their last sign-out; `ssf.addSubjects`, default true; see the README's [Subjects](../README.md#subjects-only-the-people-signed-in-here)). The subject is `iss_sub` with the transmitter's issuer, or `email` lowercased when there is no person identifier. A person identifier with no issuer is not sent. The calls run inline, once, and are not retried. A refusal names the format and not the identifier. Because a stream that names subjects carries only events about them, a receiver whose PEP wants events also adds the application itself (`{format: opaque, id: <application>}`) when it starts, before the people, and never removes it.

## Operate it

- **Health.** `gnap.pep().status()` reports whether the PEP is registered and running, whether it holds a policy, its decision counters and its current problems. It holds no secret, so it is safe on a health page. This demo does not put that document on `GET /live-status` or on a `/pep-status` route.
- **In the console.** The PEP appears under **Protocols → XACML → Remote PEPs** with its kind (`embedded`), application, mode, protocol version and whether its stream carries policy-change events. The application's page lists the PEPs bound to it.
- **Rotating the key.** Generate a new key, certify it with `issue-pep-credential`, and replace the file. The PEP reads the file again when it changes.
- **Audit.** In `local` mode each decision becomes an audit row in iya-sts. In `central` mode iya-sts records its own.

## Troubleshooting

| What you see | Likely cause |
|---|---|
| Every decision Unavailable, `status().registered` false, a problem mentioning 403 | The PEP's entry has no binding, or is bound to another application (iya-sts `STS-XACML-0338`, `0339`). Repeat step 3 with the right `application`. |
| Unavailable and a problem naming the token endpoint (`invalid_grant`) | The key isn't certified for this account, or the account isn't in `remote-peps` (steps 2 and 3). |
| Unavailable with "no policy is held yet" (`local`) | The first pull hasn't succeeded. A 403 on the policy pull (`STS-XACML-0343`) means the PEP isn't registered as an embedded `local` PEP bound to that application. |
| A registration refused with 400 (`STS-XACML-0340`) | The iya-sts release doesn't support this PEP's protocol version. Upgrade iya-sts or this library. |
| Deny saying the evaluation was refused | A resource, action or context property you sent has no catalogue row (step 4). Subject claims without a row are dropped, not refused. |
| Deny although the policy should permit | The policy reads a claim that has no catalogue row, so it never arrives (step 4). Or a Permit carried an obligation type missing from `supportedObligations`. |
| Policy changes take minutes to apply (`local`) | The stream doesn't carry the event: check `ssfAllowedEvents` (step 6) and the receiver's error line for a refused stream update. |
| The configuration is refused for the assertion key | It is the GNAP client instance key. The PEP needs a key of its own. |
| `pdpUrl` is the origin and the realm is missing | The default used `idTokenIssuer`, or the grant endpoint's path did not start with `/realm/<id>`. Set `pdpUrl`, or point `grantEndpoint` at `https://<host>/realm/<id>/gnap`. |

## Test that central and local agree

`iya-pep` holds the engine and its conformance corpus. This library does not ship `authzen_cases.json`, and `scripts/live_iya_sts.py` has no `--authzen`. `docker build --target test .` runs the GNAP wiring: the realm `pdpUrl` (and that it is not the origin of a realm URL), the subject id order, the shared-key refusal, `wantsEvents`, a `decideGrant` denial that does not ask the PDP, `ssf.addSubjects`, Add and Remove Subject, a reused stream gaining the policy event, and the opaque application subject. Those tests do not start a PEP against a PDP and do not compare `central` with `local`.

## The demo

With a `pep` section, the demo protects two routes. The status after a sign-in check is `decision.httpStatus()`.

- `/attribute-protected`, any method: `Access.of("read", "attribute-protected", "attr1")`.
- `/orders/<id>`: `read` on GET and `write` on any other method, resource type `order`, id the path segment. The usual page is `/orders/42`.

No sign-in is 401, `Sign in first`, with a link to `/login`. A Deny, an Unavailable decision, or a GNAP client that will not load is 403. The unloaded-client page says `No decision could be asked for: the GNAP client is not configured.` The reason on a decision page is `decision.why()`. Each of these responses sends `Cache-Control: no-store`. The home page links the two routes when `pep()` is non-null.

One command sets it up:

```bash
ADMIN_API_CLIENT_SECRET=… python3 scripts/configure_iya_sts.py --config demo/gnap.json --pep
```

`--pep central` selects central. `--pep` with no mode is `local`. It registers the client, then does steps 2 to 6, gives the test user `attr1=abc123` when a test user is requested, and writes `pep` (`name`, `mode`, `assertionKey: generated/pep-key.pem`) into the configuration, keeping other members. `--dry-run` prints the plan, including the key path, and prints no secret. Run again to switch the mode: the account and the key are kept, and the script's own policy is written again.

This demo does not draw a Policy enforcement tab, does not ship `pep.js`, and does not serve `GET /pep-status`. An application reads `gnap.pep().status()` itself.

### Testing the protected pages

- **Unit** (`docker build --target test .`): `PepTest`, `ConfigTest` and `SsfTest` cover the wiring listed above. They do not drive `/attribute-protected` or `/orders/42` through a `local` PEP holding the application's stored XACML.
- **Live** (`python3 scripts/live_iya_sts.py --pep`, or `LIVE_PEP=1`): opt-in. The nightly run leaves it off, because iya-sts `main` lacks the embedded PEP. The script runs the install script with `--pep central`, mounts the PEP key, requires 401 on both pages before sign-in, then 200 on `GET /attribute-protected` and `GET /orders/42` and 403 on `POST /orders/42`. It does not add a denied user, switch the running demo to `local`, rewrite the policy and wait for `pep-policies-changed`, or compare iya-sts's stored XACML with a fixture.
- **Browser.** This library has no Playwright UI run.

## See also

- [`iya-pep`'s README](https://github.com/rcbj/iya-pep-java#readme): the package's own API and every configuration member.
- iya-sts's [Remote PEP page](https://rcbj.github.io/iya-sts/v1.2.0/remote-pep.html), *An embedded PEP's application*: the service's side of the binding, registration and the scoped pull.
- iya-sts's [CAEP events page](https://rcbj.github.io/iya-sts/v1.2.0/caep-events.html): the `pep-policies-changed` event.
