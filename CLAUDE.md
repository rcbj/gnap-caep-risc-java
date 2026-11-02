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

The `test` stage runs `mvn -B test` in `maven:3.9.9-eclipse-temurin-17`. GitHub Actions uses that command. Do not run Maven on the host. The demo stage packages with `-DskipTests` in its own Maven image. Tests use an in-process stub on 127.0.0.1. They do not need a live authorization server.

## Layout

- `src/main/java/com/iyasec/gnap/` the client, key proofs (mtls, httpsig, jwsd), and `ssf/` (one poll stream)
- `src/test/java/com/iyasec/gnap/` config, subject, client, and the Shared Signals receiver
- `src/main/java/com/iyasec/gnap/demo/Demo` the HTTP demo; `demo/gnap.json` the sample configuration
- `scripts/configure_iya_sts.py` registers the app; `scripts/redirects.py` and `scripts/trust_chain.py` support it

## Demo

`docker compose up --build` builds the demo image and starts `com.iyasec.gnap.demo.Demo` in that container. `PORT` defaults to 3000 and is the bind port. Loopback redirect and finish URLs follow `PORT`. `PUBLIC_URL` or `--public-url` replaces the origin and keeps the path. `GET /healthz` returns `ok`. `ssf.pollIntervalMs` is a millisecond interval.

## Signals

Omitted or `true` keeps CAEP and RISC on, and the resolved configuration omits `signals`. `false` does not start the receiver, does not require transmitter metadata, drops `ssf.read` and `ssf.manage`, and is kept on the resolved configuration. Anything else raises `signals must be true or false`.

## License

MIT. Copyright (c) 2026 Iya CyberSecurity Solutions, LLC.

`develop` and `main` must be the same commit.
