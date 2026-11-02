# gnap-caep-risc

Server-side GNAP client. Package `com.iyasec.gnap`. The public class is `GnapClient`.

```java
GnapClient gnap = GnapClient.fromFile("gnap.json");
GnapClient.GrantResult started = gnap.requestGrant();
GnapClient.Finished done = gnap.finishRedirect(query, List.of(started.pending.id));
```

`GnapClient.resolve` and `Config.readFile` load the same JSON keys as the Node library. Methods are camelCase.

## Tests

```bash
mvn -B test
```

Tests use an in-process stub on 127.0.0.1. They do not need a live authorization server.

## Layout

- `src/main/java/com/iyasec/gnap/` the client, key proofs (mtls, httpsig, jwsd), and `ssf/` (one poll stream)
- `src/test/java/com/iyasec/gnap/` config, subject, client, and the Shared Signals receiver
- `src/main/java/com/iyasec/gnap/demo/Demo` the HTTP demo; `demo/gnap.json` the sample configuration
- `scripts/configure_iya_sts.py` registers the app; `scripts/redirects.py` and `scripts/trust_chain.py` support it

## Demo

`mvn -q exec:java` starts `com.iyasec.gnap.demo.Demo`. `PORT` defaults to 3000 and is the bind port. Loopback redirect and finish URLs follow `PORT`. `PUBLIC_URL` or `--public-url` replaces the origin and keeps the path. `GET /healthz` returns `ok`. `ssf.pollIntervalMs` is a millisecond interval.

## Signals

Omitted or `true` keeps CAEP and RISC on, and the resolved configuration omits `signals`. `false` does not start the receiver, does not require transmitter metadata, drops `ssf.read` and `ssf.manage`, and is kept on the resolved configuration. Anything else raises `signals must be true or false`.

## License

MIT. Copyright (c) 2026 Iya CyberSecurity Solutions, LLC.

`develop` and `main` must be the same commit.
