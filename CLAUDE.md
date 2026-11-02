# gnap-caep-risc

Server-side GNAP client. Package `com.iyasec.gnap`. The public class is `GnapClient`.

```java
GnapClient gnap = GnapClient.fromFile("gnap.json");
GnapClient.GrantResult started = gnap.requestGrant();
GnapClient.Finished done = gnap.finishRedirect(query, List.of(started.pending.id));
```

`GnapClient.resolve` and `Config.readFile` load the same JSON keys as the Node library. Methods are camelCase.

## Errors

`Caught.error` records a caught exception through `java.lang.System.Logger`, including the stack, and the method then throws the `GnapError` it already threw. The caught exception is the cause. `Caught.warn` is the same record when the method recovers and does not throw: a later signing key, a poll retry, a false verification, sign-out cleanup, or a handler that must still acknowledge the Security Event Token. A `catch (GnapError)` that only throws that error again is not logged a second time.

## Tests

```bash
docker build --target test .
```

The `test` stage runs `mvn -B test` (both modules) in `maven:3.9.9-eclipse-temurin-17`. GitHub Actions uses that command. Do not run Maven on the host. The demo stage packages with `-DskipTests` in its own Maven image. Tests use an in-process stub on 127.0.0.1. They do not need a live authorization server.

The stub tests do not start iya-sts. The `test` stage installs `python3` and `openssl` for `TrustChainTest`. The scripts need only Python's standard library and the `openssl` command: no `pip install` on the host. `python3 scripts/live_iya_sts.py` does start one, unless `IYA_STS_URL` names one that is already running. It runs the install script (`python3 scripts/configure_iya_sts.py`, on the host; it does not import Java) in a scratch copy of this checkout, which writes the client key and certificate and the `tlsCa` chain, then builds the demo image (which carries the chain and no key), starts it with `TLS_CA_REFRESH=0`, no CA mount and only the key and certificate files mounted, signs the demo in and checks two Shared Signals events on `GET /live-status`. The nightly workflow runs the unit suite and this script. It never binds port 3000, 8081 or 18481-18495; the defaults are 18548 and 18648. Secrets go to `docker run` as `-e NAME`. No script prints a password or secret, or a URL (trace lines carry fixed labels); a generated test-user password goes to `demo/generated/<user>.password` (mode 0600) and only that path is printed. Every `ssl` context in `scripts/` sets TLS 1.2 as the minimum.

## Layout

Two Maven modules under an aggregator `pom.xml` (which builds both and is never published):

- `library/` is `com.iyasec:gnap-caep-risc`, the library alone. Its `pom.xml` inherits nothing, so it is complete as published, and its jar carries no demo class and no bundled dependency.
  - `library/src/main/java/com/iyasec/gnap/` the client, key proofs (mtls, httpsig, jwsd), and `ssf/` (one poll stream)
  - `library/src/test/java/com/iyasec/gnap/` config, subject, client, and the Shared Signals receiver
- `demo/` is `com.iyasec:gnap-caep-risc-demo`, never published. It depends on the library and shades one runnable jar, which the image runs as `/app/gnap-caep-risc.jar`.
  - `demo/src/main/java/com/iyasec/gnap/demo/` `Demo` (the HTTP demo), `HealthCheck`, `Redirects`, `TrustChain`; `demo/gnap.json` the sample configuration; `demo/public/` the pages
  - `demo/src/test/java/com/iyasec/gnap/TrustChainTest` (the install script writes the whole chain to `tlsCa`'s path; the library trusts the provider and a reissued leaf through it, and refuses a forged leaf and a wrong name; the entrypoint refresh verifies a reissued leaf against the file, takes a new CA on first use only when the file cannot verify it, and refuses a forged leaf and a wrong name either way). It runs from the repository root, where `scripts/` and `demo/gnap.json` are.
- Keep the three `<version>`s (aggregator, library, demo) equal to `VERSION`.
- `scripts/configure_iya_sts.py` registers the app; `scripts/live_iya_sts.py` signs in against iya-sts; `scripts/redirects.py` and `scripts/trust_chain.py` (`save_trust_chain()`) support registration; the install script writes the listener CA trust chain to the file `tlsCa` names

## The iya-sts trust chain (`tlsCa`)

`tlsCa` in `demo/gnap.json` names the iya-sts TLS listener CA trust chain the library trusts. The default is `generated/idp-ca.pem`, relative to `demo/`. The value may also be `file:<path>`, `env:<NAME>`, or the PEM itself. Every certificate in it is a trust anchor, and the listener's presented chain must verify (PKIX) to one of them, so a reissued listener certificate under the same CA is still trusted. A certificate that only appears in the presented chain is not enough. The host name is checked against the certificate's subject alternative names unless `rejectUnauthorized` is false.

`scripts/configure_iya_sts.py`, the install script, writes that file. It saves the whole chain iya-sts publishes at `GET /tls/server-certificate` (leaf, TLS Issuing CA, Intermediate, Root), or the chain from the TLS handshake when that path does not answer. It prints the path, the trust anchor's subject and its SHA-256 fingerprint. Compare the anchor with the Root CA on iya-sts's PKI page.

The demo image build copies that file into the image at `/app/demo/generated/idp-ca.pem`, so the image trusts that iya-sts with no bind mount and no fetch. Run the install script before you build the image. Rebuild the image after running the install script against a different iya-sts. `.dockerignore` admits only that file from `demo/generated`. The client's private key and certificate (`generated/client.key`, `generated/client.crt`) never go into the image; compose mounts `demo/generated` at run time. A build with no chain file yet (a fresh clone, CI) still succeeds; the image then has no `tlsCa` file.

The container entrypoint also refreshes the file from the provider at start (`com.iyasec.gnap.demo.TrustChain`), because a development iya-sts makes a new CA when it restarts. The refresh first verifies the provider against the file it already has (PKIX to one of its certificates, and the host name against the leaf), which covers a reissued listener certificate. Only when that file cannot verify the chain (no file yet, or a new CA) does it take the chain on first use: the presented chain must still verify up to the top certificate it presents and name the host, and the refresh prints the trust anchor's subject and SHA-256 fingerprint to compare with the Root CA on iya-sts's PKI page. A failed refresh keeps the file from the build. `TLS_CA_REFRESH=0` turns the refresh off. `python3 scripts/trust_chain.py --config demo/gnap.json` refreshes it by hand.

The mechanism is `COPY demo demo` plus `.dockerignore`'s `demo/generated/*` and `!demo/generated/idp-ca.pem`. Do not replace it with a COPY that names the file or globs for it: when the file is absent, BuildKit fails on the missing `demo/generated` and the classic builder fails with "no source files were specified". A directory COPY of `demo/` (which always exists) succeeds in both. Before this change `.dockerignore` did not exclude `demo/generated`, and the image did not copy it either; the library trusted a listener when any presented certificate matched one in `tlsCa`, which an impostor could satisfy by sending the public CA certificates after a leaf of its own. `TrustChainTest` holds both.

## Demo

`docker compose up --build` builds the demo image and starts `com.iyasec.gnap.demo.Demo` in that container. `PORT` defaults to 3000 and is the bind port. Loopback redirect and finish URLs follow `PORT`. `PUBLIC_URL` or `--public-url` replaces the origin and keeps the path. `GET /healthz` returns `ok`. `GET /live-status` reports the sign-in and the Shared Signals events this process has accepted. It does not include tokens. `ssf.pollIntervalMs` is a millisecond interval.

## Signals

Omitted or `true` keeps CAEP and RISC on, and the resolved configuration omits `signals`. `false` does not start the receiver, does not require transmitter metadata, drops `ssf.read` and `ssf.manage`, and is kept on the resolved configuration. Anything else raises `signals must be true or false`.

## License

MIT. Copyright (c) 2026 Iya CyberSecurity Solutions, LLC.

`develop` and `main` must be the same commit.

## Releases

A pull request merged into `main` publishes the library (`library/` only; the demo never) to Maven Central after the test workflow succeeds on that commit. A direct push does not. `publish.yml` runs `mvn -Prelease -f library/pom.xml deploy` in the Maven container: the `release` profile adds the sources and javadoc jars, a GPG signature on every file, and the Central publishing plugin, which uploads, publishes and waits until the release is live. Maven Central has no trusted publishing, so the job uses four repository secrets: `CENTRAL_TOKEN_USERNAME` and `CENTRAL_TOKEN_PASSWORD` (a Central Portal user token) and `GPG_PRIVATE_KEY` and `GPG_PASSPHRASE` (the release signing key, whose public half is on a public key server). A release on Central is permanent: a version already there is skipped, and the next release is a new version in `VERSION` and the three poms. `-Dcentral.skipPublishing=true` builds and signs everything and uploads nothing.
