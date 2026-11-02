# syntax=docker/dockerfile:1

# `docker build --target test` runs the suite in this image.
# The demo image below does not run it.
FROM maven:3.9.9-eclipse-temurin-17 AS test
WORKDIR /src
COPY pom.xml .
COPY src src
RUN mvn -B test

FROM maven:3.9.9-eclipse-temurin-17 AS build
WORKDIR /src
COPY pom.xml .
COPY src src
RUN mvn -B -DskipTests package

FROM eclipse-temurin:17-jre
WORKDIR /app
COPY --from=build /src/target/gnap-caep-risc-0.1.0.jar /app/gnap-caep-risc.jar
COPY demo/gnap.json demo/gnap.json
COPY demo/public demo/public
COPY scripts scripts
COPY demo/entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh
EXPOSE 3000
ENV PORT=3000
HEALTHCHECK --interval=15s --timeout=3s --start-period=20s \
  CMD java -cp /app/gnap-caep-risc.jar com.iyasec.gnap.demo.HealthCheck || exit 1
ENTRYPOINT ["/entrypoint.sh"]
CMD ["java", "-jar", "/app/gnap-caep-risc.jar"]
