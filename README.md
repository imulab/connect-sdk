# Connect SDK 🚅

> Make providing Open ID Connect service easier!

<img align="right" src="./doc/assets/openid-logo.png" height="170">

**Connect SDK** provides the following features out of the box:
- Support for authorize code flow, hybrid flow, implicit flow and client credentials flow
- HMAC-SHA256 based authorize code
- JWT based access token
- HMAC-SHA256 based refresh token
- JWT/JWE based id token
- Support for all token endpoint authentication methods
- Support to parse parameters from HTTP request, request parameter and/or default values.

*The SDK is designed with interfaces in mind, it can always to be extended to fit customized needs.*

## Install

### Gradle

Add to repositories

```groovy
repositories {
    maven {
        url  "https://dl.bintray.com/imulab/connect-sdk" 
    }
}
```

Add to dependencies

```groovy
compile 'io.imulab:connect-sdk:0.1.1'
```

### Maven

Add to repositories

```xml
<repository>
    <id>bintray-imulab-connect-sdk</id>
    <name>bintray</name>
    <url>https://dl.bintray.com/imulab/connect-sdk</url>
</repository>
```

Add to dependencies

```xml
<dependency>
  <groupId>io.imulab</groupId>
  <artifactId>connect-sdk</artifactId>
  <version>0.1.1</version>
</dependency>
```

## How-To

- [Setup the flow handler](./doc/flow_example.md)
- More to come

## Interface

**Connect SDK** is designed to do the heavy lifting, but still leaves the choice of technology stack to users. It only depends on three libraries, namely `kotlin-stdlib`, `kotlin-coroutine` and `jose4j`. 

In order to achieve this, the library had left several **service provider interfaces** for users to adapt to their own library of choice:

<details>
  <summary><strong>Service Provider Interfaces</strong> (click to expand)</summary>

- `HttpClient` - for making HTTP calls, mainly to resolve non-cached request object or client JWKS.
- `HttpRequest` - for parsing HTTP request data, used heavily in request parsers.
- `JsonProvider` - for parsing JSON objects, used mainly for parsing the claim parameter to Map.
- `SecretComparator` - for comparing client secrets, used in secret based authenticators. The default implementation uses string equality comparison.
- `Client` - users shall provide their own client data model and it can be enabled to persist in any ways.
- `ClientSecretAware` - optional interface if the user decide to utilize secret based authentication.
- `JwksCacheAware` - optional interface if the user decides to cache the client JWKS obtained during client registration.
- `RequestCacheAware` - optional interface if the user decides to cache the request object obtained during client registration.
- `AuthorizeCodeRepository` - interface to provide storage capability for authorize code and its related session
- `AccessTokenRepository` - interface to provide storage capability for access token and its related session
- `RefreshTokenRepository` - interface to provide storage capability for refresh token and its related session

</details>

In addition to that, out of box features also uses interfaces that can be re-implemented. These interfaces include:

<details>
  <summary><strong>Extension Point Interfaces</strong> (click to expand)</summary>

- `AuthorizeHandler` - handles authorize endpoint request
- `TokenHandler` - handles token endpoint request
- `Authenticator` - handles token endpoint authentication
- `AuthorizeRequestParser` - parses parameters for the authorize endpoint request
- `TokenRequestParser` - parses parameters for the token endpoint request
- `AuthorizeCodeStrategy` - handles algorithms to generate and validate authorize code
- `AccessTokenStrategy` - handles algorithms to generate and validate access token
- `RefreshTokenStrategy` - handles algorithms to generate and validate refresh token
- `IdTokenStrategy` - handles algorithms to generate id token

</details>

# License

The MIT License (MIT) 2019 - [Weinan Qiu](https://github.com/imulab/). Please have a look at the [LICENSE](LICENSE) for more details.