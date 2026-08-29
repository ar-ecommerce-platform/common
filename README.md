# common

Shared Java library for the [ar-ecommerce-platform](https://github.com/ar-ecommerce-platform).

Holds `JwtUtils` — a plain (non-Spring) HS256 helper for generating and parsing tokens, with an
injectable `Clock` for testability.

Not currently wired into any service; `auth-service` has its own smaller JWT helper.

## Build

```bash
./gradlew build
```

`java-library` plugin only — no Spring Boot, no `bootJar`.

## Tech

Java 21 · jjwt 0.13 · JUnit 5 · Gradle
