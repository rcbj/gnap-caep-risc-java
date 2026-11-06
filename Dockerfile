# syntax=docker/dockerfile:1

# `docker build --target test` runs the suite in this image.
# The demo image below does not run it.
FROM maven:3.9.9-eclipse-temurin-17 AS test
# TrustChainTest runs the install script's trust-chain code, which is Python.
RUN apt-get update && apt-get install -y --no-install-recommends python3 openssl && rm -rf /var/lib/apt/lists/*
WORKDIR /src
# Both modules: library/ (the published library) and demo/ (the demo, and
# TrustChainTest, which runs scripts/ against demo/gnap.json).
COPY pom.xml .
COPY library library
COPY demo/pom.xml demo/pom.xml
COPY demo/src demo/src
COPY scripts scripts
COPY demo/gnap.json demo/gnap.json
RUN mvn -B test

FROM maven:3.9.9-eclipse-temurin-17 AS build
WORKDIR /src
COPY pom.xml .
COPY library library
COPY demo/pom.xml demo/pom.xml
COPY demo/src demo/src
RUN mvn -B -DskipTests package

FROM eclipse-temurin:25-jre
WORKDIR /app
# The demo module's runnable jar (the demo, the library and its dependencies),
# under the name the entrypoint and the health check have always used.
COPY --from=build /src/demo/target/gnap-caep-risc-demo-0.1.1.jar /app/gnap-caep-risc.jar
COPY scripts scripts
# The demo, and with it tlsCa's file: demo/generated/idp-ca.pem, the iya-sts
# listener CA trust chain scripts/configure_iya_sts.py saved. The image trusts
# that iya-sts with no bind mount and no fetch. Rebuild after running the
# install script against a different iya-sts.
# .dockerignore admits that one file from demo/generated (never the client's
# private key or certificate). A COPY of the demo DIRECTORY succeeds with or
# without it, so a fresh clone and CI still build; naming the file, or a glob
# that matches nothing, fails the build in both builders.
COPY demo demo
COPY demo/entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh
EXPOSE 3000
ENV PORT=3000
HEALTHCHECK --interval=15s --timeout=3s --start-period=20s \
  CMD java -cp /app/gnap-caep-risc.jar com.iyasec.gnap.demo.HealthCheck || exit 1
ENTRYPOINT ["/entrypoint.sh"]
CMD ["java", "-jar", "/app/gnap-caep-risc.jar"]
