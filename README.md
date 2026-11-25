# gnap-caep-risc

A server-side [GNAP](https://www.rfc-editor.org/rfc/rfc9635) client. The key is registered by value and proved with mutual TLS, an HTTP message signature, or a detached JWS. Access tokens are key-bound; a bearer token is refused. One Shared Signals poll stream carries CAEP and RISC events.

The private key stays in this process. The same `gnap.json` shape as the Node library loads: the JSON keys are identical. A `pep` section embeds an iya-sts Remote PEP. [docs/remote-pep.md](docs/remote-pep.md) is the guide.

## Build and tests

The build and the tests run in a container.

```bash
docker build --target test .
```

Bytecode is 17. The test image is `maven:3.9-eclipse-temurin-26`. The demo runtime image is `eclipse-temurin:25-jre`. That target runs the suite in the Maven image. The test stage and the build stage each clone `https://github.com/rcbj/iya-pep-java.git` branch `develop` and install `com.iyasec:iya-pep:0.1.0` before Maven runs the suite or the package. A clone that fails because `develop` is not pushed is left failed. The repository has two Maven modules: `library/` is the library (`com.iyasec:gnap-caep-risc`, nothing else in its jar) and `demo/` is the demo, which depends on it and is never published. The demo image is a later stage and does not run the suite. `docker compose up --build` builds that image and starts the demo.

The suite includes `TrustChainTest`, which runs the install script's trust-chain code (Python, installed in the `test` stage) against an HTTPS stub on a four-certificate chain and checks the library trusts the stub through the file it wrote, trusts a reissued leaf from the same CA, and refuses a forged leaf and a wrong host name.

`python3 scripts/live_iya_sts.py` is the live half. It starts a fresh iya-sts when `IYA_STS_URL` is unset, runs `python3 scripts/configure_iya_sts.py` on the host in a scratch copy of this checkout (it registers the demo, writes the client key and certificate, and writes the `tlsCa` chain), then builds this demo image from it, checks the image carries the chain and no key, starts the demo with only the key and certificate files mounted and `TLS_CA_REFRESH=0`, signs in, and requires a credential-change event and a session-revoked event on `GET /live-status`. The second event ends the local session. It never binds port 3000, 8081 or 18481-18495; its defaults are 18548 (`LIVE_STS_PORT`) and 18648 (`LIVE_DEMO_PORT`). Secrets go to `docker run` as `-e NAME`. It needs `python3` (standard library only), `openssl` and Docker on the host, and installs nothing. When `configure_iya_sts.py` generates a test-user password it writes it to `demo/generated/<user>.password` (mode 0600) and prints only that path. The nightly workflow runs the unit suite and this script.

The artifact is `com.iyasec:gnap-caep-risc:0.1.1`. This work stays on `develop` until `com.iyasec:iya-pep:0.1.0` is on Maven Central: a merge to `main` publishes the library, and that publish cannot depend on a git pin. A pull request merged into `main` publishes the library (`library/` only; the demo never) to Maven Central after the test workflow succeeds on that commit. A direct push does not. `publish.yml` runs `mvn -Prelease -f library/pom.xml deploy` in the Maven container: the `release` profile adds the sources and javadoc jars, a GPG signature on every file, and the Central publishing plugin, which uploads, publishes and waits until the release is live. Maven Central has no trusted publishing, so the job uses four repository secrets: `CENTRAL_TOKEN_USERNAME` and `CENTRAL_TOKEN_PASSWORD` (a Central Portal user token) and `GPG_PRIVATE_KEY` and `GPG_PASSPHRASE` (the release signing key, whose public half is on a public key server). A release happens when the library's files changed since the last release's tag: `publish.yml` takes one patch above the highest published version, publishes it, and creates the matching tag and GitHub Release. A change to tests, the demo, or the docs releases nothing. To choose a version or start a new minor, raise `VERSION`; the version is stamped in CI and is not committed, so the manifests can trail what is published. `-Dcentral.skipPublishing=true` builds and signs everything and uploads nothing.

## Three calls

```java
import com.iyasec.gnap.GnapClient;

GnapClient gnap = GnapClient.fromFile("gnap.json");
GnapClient.GrantResult started = gnap.requestGrant();
GnapClient.Finished done = gnap.finishRedirect(query, List.of(started.pending.id));
```

`requestGrant` returns a redirect and a pending grant. `finishRedirect` checks the interaction hash against grants this process started, then continues the grant with the key proof. Pass the pending ids this browser was given.

`GnapClient.resolve` and `Config.readFile` load the same document without starting a grant.

## Signals

`signals` omitted or `true` keeps CAEP and RISC on. The resolved configuration omits the key, fills `ssf` from `ssf.transmitter` or `transmitterIssuer`, and asks for `ssf.read` and `ssf.manage` when `access` does not say otherwise.

`signals: false` does not start the Shared Signals receiver, does not require transmitter metadata, and drops `ssf.read` and `ssf.manage` from the GNAP access. The resolved configuration includes `signals: false`. If those two rights were the only ones, configuration fails and asks for another right the authorization server grants. Any other value fails with `signals must be true or false`.

`ssf.pollIntervalMs` is the poll interval in milliseconds. `SignalsReceiver.stop` marks the PEP's stream down and returns without waiting for the poll thread.

### Subjects: only the people signed in here

The receiver tells the transmitter which people are signed in here, so the stream carries events about them.

- **Sign-in.** `track` calls Add Subject (`add_subject_endpoint`, body `stream_id`, `subject`, `verified: true`) for a person not yet accepted. The subject is `iss_sub` with the transmitter's issuer when the person identifier is non-empty. A person with no issuer is not sent. Otherwise the subject is `email`, lowercased. A person tracked before `start` is added by `start`.
- **Sign-out.** `untrack`, and an event that ends a sign-in, calls Remove Subject when no other tracked sign-in maps to that subject and the transmitter accepted it. Re-tracking the same local id keeps the person.
- **Failures.** A refusal is reported once, with the subject format and no identifier, and is not retried. A missing endpoint means no call. The sign-in still completes.
- **Turning it off.** `ssf.addSubjects: false` (default `true`) turns it off. The value must be a boolean when a transmitter is configured.
- **The PEP's events.** When the embedded PEP wants policy events, `start` also adds the application, `{format: opaque, id: <application>}`, first, and never removes it.
- **Expired sign-ins.** A tracked sign-in that expires without `untrack` stays subscribed at the transmitter.
- **The demo.** It tracks every sign-in. Logout untracks the same local id.

## Embedded PEP

Ask iya-sts's authorization policy whether the person a grant names may act on a resource. The PEP is [`com.iyasec:iya-pep`](https://github.com/rcbj/iya-pep-java) 0.1.0 (iya-sts [#1206](https://github.com/rcbj/iya-sts/issues/1206)). **[docs/remote-pep.md](docs/remote-pep.md)** is the full guide: setting up iya-sts, `central` or `local`, every configuration member, obligations, policy-change events and troubleshooting.

```json
"pep": { "name": "pep-orders", "mode": "local", "assertionKey": "pep-key.pem" }
```

```java
Decision decision = gnap.decideGrant(grant, Access.of("read", "order", "42"));
int status = decision.httpStatus(); // 200 for a Permit, 403 for anything else
```

The section is off unless present. There is no separate build flag. A missing `mode` is `local`. `pdpUrl` defaults to the grant endpoint's realm (`/realm/<id>` kept; a named server segment and `/gnap` dropped; otherwise the origin). `application` defaults to the configuration's `application`. The subject's id is `uid` from the `account` identifier, else the assertion's `username`, else `preferred_username`, else `sub`. `decideGrant` denies, without asking, a grant with no subject, one this client revoked, or one whose access token has expired. Every PEP failure is a 403. The demo protects `/attribute-protected` and `/orders/<id>` with `httpStatus()`: 401 signed out, 403 on a Deny or any failure.

## Credentials

Every credential the library, its demo and its embedded PEP hold, who makes each one, and what it proves. No value of any of them is in this repository, in the demo image, or in a log line. The demo keeps its key material in `demo/generated/`, which `.gitignore` and `.dockerignore` keep out (only the public `tlsCa` chain enters the image).

### The application's own credentials

| Credential | Type | Made or issued by | Where it lives | Used for | How iya-sts knows it | Rotation |
|---|---|---|---|---|---|---|
| **Client instance key** and its certificate | EC P-256 (ES256) in the demo; the library also loads RSA keys | You, with `openssl` (a self-signed certificate; `scripts/live_iya_sts.py` makes one the same way). The install script registers that public key. It does not call `issue-tls-client-certificate` | `privateKey` and `certificate` (`file:`, `env:` or inline PEM): the demo's are `file:generated/client.key` and `file:generated/client.crt`. Keep the key readable by you only | Proves every GNAP request: `keyProof` `mtls` (this same key as the TLS client certificate), `httpsig` or `jwsd`. Every access token is bound to it; a bearer token is refused | The application entry's `gnapKey`, written when the install script creates the application: the certificate under `mtls`, the public JWK otherwise | Creating the application writes `gnapKey`. A later run of the install script leaves `gnapKey` as it is. Set it yourself when the key changes |
| **GNAP access token** | Key-bound token | iya-sts, at the end of a grant | In process memory only (the demo's session table). Pages do not show it | The grant's access rights (`ssf.read`, `ssf.manage` in the demo), sent with the key proof | It issued it | `ensureFresh` rotates it through the management URI when 60 s or less are left |
| **Management access token** | Key-bound token | iya-sts, with the grant | Memory only | Rotating the access token (`rotate`) | It issued it | Comes back with each rotation |
| **Continuation access token** | Key-bound token | iya-sts, with the pending and the finished grant | Memory only | Continuing the grant after interaction (`finishRedirect`), and revoking it (`revoke`, a DELETE of the continuation URI at sign-out) | It issued it | Per grant |
| **The token for Shared Signals calls** | The GNAP access token above | — | Memory only | Stream discovery, creation, update, polls and verification. The demo signs each call with the latest grant's access token and the client instance key's proof. There is no separate Shared Signals TLS client key | The `ssf.read` / `ssf.manage` rights on that token | Follows the access token |
| **The test user's password** (demo only) | Password | iya-sts generates it, or you give `GNAP_DEMO_USER_PASSWORD` | `demo/generated/<user>.password`, created 0600, only when iya-sts generated it; only the path is printed | Signing in to iya-sts as `gnap-demo-user` to try the demo | The directory | Set `GNAP_DEMO_USER_PASSWORD` and run the install script again: an existing user's password is set to it |

### The embedded PEP's credentials

The PEP is a principal of its own: the service account `pep-gnap-demo` (`--pep-name`), created with no password (`credential: none`) as a service account and put in the `remote-peps` group.

| Credential | Type | Made or issued by | Where it lives | Used for | How iya-sts knows it | Rotation |
|---|---|---|---|---|---|---|
| **PEP key** | EC P-256 | Made locally with `openssl` by the install script, only when the file is missing. Only its certificate request is sent. The key material is never printed | `pep.assertionKey`, relative to the configuration's directory. The demo's is `generated/pep-key.pem`, created 0600, never in the image | Signs an RFC 7523 JWT assertion (`iss` and `sub` the PEP's name) at the realm's token endpoint (client `sts-remote-pep`), and the DPoP proof of every PEP call | `issue-pep-credential` certifies the request, registers the key, and binds the PEP to the application. A kept key and a kept account use `set-pep-application` instead | Delete `demo/generated/pep-key.pem` and run the install script again. It makes and certifies a new key and keeps the account. The library refuses a PEP key whose JWK thumbprint equals the client instance key |

### Install-time only

| Credential | Type | Where it lives | Used for |
|---|---|---|---|
| Management client secret | `ADMIN_API_CLIENT_SECRET` or `STS_ADMIN_API_CLIENT_SECRET` | The environment, never a file this script writes | Minting the token for `/admin-api`. Defining `attr1` uses a separate token with `admin:read admin:security` for that call alone, and only when `--pep` and a test user are both set |

The PEP never sees that secret.

### Trust material

| Material | Where it lives | Used for |
|---|---|---|
| iya-sts listener CA chain | `tlsCa`, demo default `generated/idp-ca.pem` (the one generated file the image copies in) | TLS to iya-sts for GNAP, Shared Signals and the PEP. `pep.tlsCa` defaults to this PEM when the section omits it and the value contains a certificate |
| Transmitter JWKS | Fetched, not stored | Verifying Security Event Tokens, including `pep-policies-changed` |

### Development and product iya-sts

The client instance key is the key you generate, in both. The install script registers its public half when it creates the application and leaves that registration on a later run. The mTLS certificate is that same key. The PEP key is certified by `issue-pep-credential` the same way in both. A development iya-sts makes a new listener CA when it restarts: run the install script again (it rewrites `tlsCa`'s file) and rebuild the demo image, or let the demo's start-time refresh fetch it (`TLS_CA_REFRESH`, on by default). In product the chain is stable.

## Demo

```bash
docker compose up --build
```

`PORT` defaults to 3000 and is the bind port. Loopback finish and display URLs follow `PORT`. Any other host is left as written. `PUBLIC_URL` or `--public-url` replaces the origin and keeps the path. `GET /healthz` returns `ok`. The home page has a sign-in control; `/login` starts a grant, `/callback` finishes it, and `POST /logout` signs out. `GET /live-status` is JSON for the sign-in and the Shared Signals events this process has accepted: `signedIn`, `subject`, `receiver`, and events of `type` and `jti`. It does not include tokens.

The shipped `demo/gnap.json` leaves `signals` on by omitting the key. Key material is `file:` or `env:` and is not in the tree. Generate a key, then register the application with the Python registrar in this repo:

```bash
ADMIN_API_CLIENT_SECRET=… python3 scripts/configure_iya_sts.py --config demo/gnap.json
```

`--dry-run` prints the admin API calls and sends nothing. When the `gnap-demo` container is running, its `PORT` wins over the shell `PORT`.

### The demo with its embedded PEP

```bash
ADMIN_API_CLIENT_SECRET=… python3 scripts/configure_iya_sts.py --config demo/gnap.json --pep
docker compose up --build
```

`--pep` with no mode is `local`. `--pep central` selects central. `--pep-name` defaults to `pep-gnap-demo`. The script does [docs/remote-pep.md](docs/remote-pep.md)'s steps 2 to 6: the PEP's service account in `remote-peps`, a P-256 key in `demo/generated/pep-key.pem` (0600, never printed, never in the image), the key certified and the PEP bound to the demo's application, the catalogue row `subject.acr` → `urn:example:acr`, and the application's own policy. Read on an order needs an `acr`. Read on `attribute-protected` needs the directory attribute `attr1` to be `abc123`. Anything else is denied. The realm root is left alone. The policy is written again while its PolicyId is `urn:example:gnapdemo-orders`. A policy under any other PolicyId is left as it is. Run it again to switch the mode: the account and the key are kept. `--dry-run` lists these calls and sends nothing.

With a `pep` section the home page links `/attribute-protected` and `/orders/42`. No sign-in is 401, `Sign in first`. After that the status is `decision.httpStatus()`: 200 on a Permit, 403 on a Deny and on any failure, including a GNAP client that will not load. `GET /attribute-protected` is `read` on resource type `attribute-protected`, id `attr1`. `GET /orders/42` is `read` on an `order`; any other method is `write`. Each page sends `Cache-Control: no-store`. The install script gives the test user `attr1=abc123` when `--pep` names a test user. Defining that realm attribute uses one `admin:security` token. Where that call is refused, the value is still tried.

Enforcing the demo application's policy decides nothing at GNAP issuance: its grant asks for plain access rights (`ssf.read`, `ssf.manage`), and iya-sts asks an application's policy only about an `authorization_details` type that application declares.

`python3 scripts/live_iya_sts.py --pep` (or `LIVE_PEP=1`) is opt-in. The nightly run leaves it off, because iya-sts `main` lacks the embedded PEP. It configures `central`, mounts the PEP key, requires 401 on both pages before sign-in, then 200 on `GET /attribute-protected` and `GET /orders/42` and 403 on `POST /orders/42`.

## The iya-sts trust chain (`tlsCa`)

`tlsCa` in `demo/gnap.json` names the iya-sts TLS listener CA trust chain the library trusts. The default is `generated/idp-ca.pem`, relative to `demo/`. The value may also be `file:<path>`, `env:<NAME>`, or the PEM itself. Every certificate in it is a trust anchor, and the listener's presented chain must verify (PKIX) to one of them, so a reissued listener certificate under the same CA is still trusted. A certificate that only appears in the presented chain is not enough. The host name is checked against the certificate's subject alternative names unless `rejectUnauthorized` is false.

`scripts/configure_iya_sts.py`, the install script, writes that file. It saves the whole chain iya-sts publishes at `GET /tls/server-certificate` (leaf, TLS Issuing CA, Intermediate, Root), or the chain from the TLS handshake when that path does not answer. It prints the path, the trust anchor's subject and its SHA-256 fingerprint. Compare the anchor with the Root CA on iya-sts's PKI page.

The demo image build copies that file into the image at `/app/demo/generated/idp-ca.pem`, so the image trusts that iya-sts with no bind mount and no fetch. Run the install script before you build the image. Rebuild the image after running the install script against a different iya-sts. `.dockerignore` admits only that file from `demo/generated`. The client's private key and certificate (`generated/client.key`, `generated/client.crt`) never go into the image; compose mounts `demo/generated` at run time. A build with no chain file yet (a fresh clone, CI) still succeeds; the image then has no `tlsCa` file.

The container entrypoint also refreshes the file from the provider at start (`com.iyasec.gnap.demo.TrustChain`), because a development iya-sts makes a new CA when it restarts. The refresh first verifies the provider against the file it already has (PKIX to one of its certificates, and the host name against the leaf), which covers a reissued listener certificate. Only when that file cannot verify the chain (no file yet, or a new CA) does it take the chain on first use: the presented chain must still verify up to the top certificate it presents and name the host, and the refresh prints the trust anchor's subject and SHA-256 fingerprint to compare with the Root CA on iya-sts's PKI page. A failed refresh keeps the file from the build. `TLS_CA_REFRESH=0` turns the refresh off. `python3 scripts/trust_chain.py --config demo/gnap.json` refreshes it by hand.

## Errors

A caught exception is written to `java.lang.System.Logger` with its stack. The JDK sends that logger to `java.util.logging` unless the application installs a `System.LoggerFinder`. Where this library already threw `GnapError`, it still throws `GnapError`, and the caught exception is the cause.

A catch that recovers does not throw. It is still logged. A poll is retried, the next signing key is tried, an HTTP error body is read, sign-out still finishes after a revoke fails, and a Shared Signals handler that throws does not stop acknowledgement of that event. Passing a `GnapError` through is not logged again: the foreign exception was logged where it was caught.

## License

MIT. Copyright (c) 2026 Iya CyberSecurity Solutions, LLC.
