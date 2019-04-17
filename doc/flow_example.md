# Flow

The main interface for flow handlers are `AuthorizeHandler` and `TokenHandler`. As their names hinted, they take care of the request from the authorize endpoint and token endpoint respectively.

Some flow, for instance, implicit flow, utilizes only one endpoint. Others, for instance, hybrid flow, utilizes both endpoints.

The main entry point of requests is `ConnectHandler`. It consists of a list of `AuthorizeHandler` implementations and another list of `TokenHandler` implementations.

```kotlin
class ConnectHandler(
    private val authorizeHandlers: List<AuthorizeHandler>,
    private val tokenHandlers: List<TokenHandler>
)
```

To setup, for example, a service capable of handling authorizing code flow and implicit flow, one will do the following:

```kotlin
/*
 * Setup for authorizeCodeHelper, accessTokenHelper, refreshTokenHelper, idTokenHelper is omitted.
 */

// authorize code flow can issue authorize code in the authorize leg, and
// access token (optionally refresh token and id token) in the token leg
val authorizeCodeFlowHandler = AuthorizeCodeFlowHandler(
    authorizeCodeHelper = authorizeCodeHelper,
    accessTokenHelper = accessTokenHelper,
    refreshTokenHelper = refreshTokenHelper,
    idTokenHelper = idTokenHelper
)

// implicit flow can issue access token and optionally id token in the authorize leg
val implicitFlowHandler = ImplicitFlowHandler(
    accessTokenHelper = accessTokenHelper,
    idTokenHelper = idTokenHelper
)

val handler = ConnectHandler(
  authorizeHandlers = listOf(
      authorizeCodeFlowHandler,
      implicitFlowHandler
  ),
  tokenHandlers = listOf(
      authorizeCodeFlowHandler
  )
)

handler.handleAuthorizeRequest(request, response)
handler.handleTokenRequest(request, response)
```

For a more comprehensive setup example, please see [HandlerTest](https://github.com/imulab/connect-sdk/blob/master/src/test/kotlin/io/imulab/connect/HandlerTest.kt).