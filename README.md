# gnap-caep-risc

A server-side [GNAP](https://www.rfc-editor.org/rfc/rfc9635) client. The key is registered by value and proved with mutual TLS, an HTTP message signature, or a detached JWS. Access tokens are key-bound; a bearer token is refused. One Shared Signals poll stream carries CAEP and RISC events.

The private key stays in this process. The same `gnap.json` shape as the Node library loads: the JSON keys are identical.

## Build and tests

The build and the tests run in a container.

```bash
docker build --target test .
```

That target runs the suite in the Maven image. The demo image is a later stage and does not run the suite. `docker compose up --build` builds that image and starts the demo.

The suite includes `TrustChainTest`, which runs the install script's trust-chain code (Python, installed in the `test` stage) against an HTTPS stub on a four-certificate chain and checks the library trusts the stub through the file it wrote, trusts a reissued leaf from the same CA, and refuses a forged leaf and a wrong host name.

`python3 scripts/live_iya_sts.py` is the live half. It starts a fresh iya-sts when `IYA_STS_URL` is unset, runs `python3 scripts/configure_iya_sts.py` on the host in a scratch copy of this checkout (it registers the demo, writes the client key and certificate, and writes the `tlsCa` chain), then builds this demo image from it, checks the image carries the chain and no key, starts the demo with only the key and certificate files mounted and `TLS_CA_REFRESH=0`, signs in, and requires a credential-change event and a session-revoked event on `GET /live-status`. The second event ends the local session. It never binds port 3000, 8081 or 18481-18495; its defaults are 18548 (`LIVE_STS_PORT`) and 18648 (`LIVE_DEMO_PORT`). Secrets go to `docker run` as `-e NAME`. The nightly workflow runs the unit suite and this script.

The artifact is `com.iyasec:gnap-caep-risc:0.1.0`. Maven publishing is not set up yet.

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

`ssf.pollIntervalMs` is the poll interval in milliseconds.

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

## The iya-sts trust chain (`tlsCa`)

`tlsCa` in `demo/gnap.json` names the iya-sts TLS listener CA trust chain the library trusts. The default is `generated/idp-ca.pem`, relative to `demo/`. The value may also be `file:<path>`, `env:<NAME>`, or the PEM itself. Every certificate in it is a trust anchor, and the listener's presented chain must verify (PKIX) to one of them, so a reissued listener certificate under the same CA is still trusted. A certificate that only appears in the presented chain is not enough. The host name is checked against the certificate's subject alternative names unless `rejectUnauthorized` is false.

`scripts/configure_iya_sts.py`, the install script, writes that file. It saves the whole chain iya-sts publishes at `GET /tls/server-certificate` (leaf, TLS Issuing CA, Intermediate, Root), or the chain from the TLS handshake when that path does not answer. It prints the path, the trust anchor's subject and its SHA-256 fingerprint. Compare the anchor with the Root CA on iya-sts's PKI page.

The demo image build copies that file into the image at `/app/demo/generated/idp-ca.pem`, so the image trusts that iya-sts with no bind mount and no fetch. Run the install script before you build the image. Rebuild the image after running the install script against a different iya-sts. `.dockerignore` admits only that file from `demo/generated`. The client's private key and certificate (`generated/client.key`, `generated/client.crt`) never go into the image; compose mounts `demo/generated` at run time. A build with no chain file yet (a fresh clone, CI) still succeeds; the image then has no `tlsCa` file.

The container entrypoint also refreshes the file from the provider at start (`com.iyasec.gnap.demo.TrustChain`), because a development iya-sts makes a new CA when it restarts. A failed refresh keeps the file from the build. `TLS_CA_REFRESH=0` turns the refresh off. `python3 scripts/trust_chain.py --config demo/gnap.json` refreshes it by hand.

## Errors

A caught exception is written to `java.lang.System.Logger` with its stack. The JDK sends that logger to `java.util.logging` unless the application installs a `System.LoggerFinder`. Where this library already threw `GnapError`, it still throws `GnapError`, and the caught exception is the cause.

A catch that recovers does not throw. It is still logged. A poll is retried, the next signing key is tried, an HTTP error body is read, sign-out still finishes after a revoke fails, and a Shared Signals handler that throws does not stop acknowledgement of that event. Passing a `GnapError` through is not logged again: the foreign exception was logged where it was caught.

## License

MIT. Copyright (c) 2026 Iya CyberSecurity Solutions, LLC.
