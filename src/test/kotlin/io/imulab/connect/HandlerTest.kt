package io.imulab.connect

import com.nhaarman.mockitokotlin2.doReturn
import com.nhaarman.mockitokotlin2.mock
import io.imulab.connect.client.*
import io.imulab.connect.handler.*
import io.kotlintest.matchers.numerics.shouldBeGreaterThan
import io.kotlintest.matchers.string.shouldBeEmpty
import io.kotlintest.matchers.string.shouldNotBeEmpty
import io.kotlintest.shouldBe
import io.kotlintest.shouldNotBe
import io.kotlintest.shouldNotThrowAny
import io.kotlintest.shouldThrowExactly
import io.kotlintest.specs.FeatureSpec
import org.jose4j.jwk.JsonWebKeySet
import org.jose4j.jwk.RsaJwkGenerator
import org.jose4j.jwk.Use
import org.jose4j.keys.AesKey
import java.nio.charset.StandardCharsets
import java.time.Duration
import java.time.LocalDateTime
import java.util.*

class HandlerTest : FeatureSpec({

    feature("authorize code flow") {
        val handler = masterHandler()

        scenario("""
            receive authorize code and use it to exchange for access token, refresh token and id token
        """.trimIndent()) {
            // authorize leg
            val authorizeResponse: Response = mutableMapOf()
            val authorizeRequest = ConnectAuthorizeRequest(
                id = UUID.randomUUID().toString(),
                requestedAt = LocalDateTime.now(),
                _client = sampleClient,
                redirectUri = "https://test.org/callback",
                responseTypes = mutableSetOf(ResponseType.CODE),
                scopes = mutableSetOf("foo", "bar", OPEN_ID, OFFLINE_ACCESS),
                state = "12345678",
                nonce = "87654321",
                session = ConnectSession(
                    subject = "test-user",
                    obfuscatedSubject = "test-user-obfuscated",
                    nonce = "87654321",
                    clientId = sampleClient.id,
                    grantedScopes = mutableSetOf("foo", OPEN_ID, OFFLINE_ACCESS),
                    finalRedirectUri = "https://test.org/callback",
                    authTime = LocalDateTime.now().minusMinutes(5)
                )
            )

            handler.handleAuthorizeRequest(request = authorizeRequest, response = authorizeResponse)

            val code = authorizeResponse.getCode()
            code.shouldNotBeEmpty()

            // token leg
            val tokenResponse: Response = mutableMapOf()
            val tokenRequest = ConnectTokenRequest(
                id = UUID.randomUUID().toString(),
                requestedAt = LocalDateTime.now(),
                _client = sampleClient,
                redirectUri = "https://test.org/callback",
                code = code,
                grantTypes = mutableSetOf(GrantType.CODE),
                session = ConnectSession()
            )

            handler.handleTokenRequest(request = tokenRequest, response = tokenResponse)

            tokenResponse.getAccessToken().shouldNotBeEmpty()
            tokenResponse.getIdToken().shouldNotBeEmpty()
            tokenResponse.getRefreshToken().shouldNotBeEmpty()
            tokenResponse.getTokenType() shouldBe "Bearer"
            tokenResponse.getExpiresIn() shouldBeGreaterThan 0

            // refresh leg
            val refreshResponse: Response = mutableMapOf()
            val refreshRequest = ConnectTokenRequest(
                id = UUID.randomUUID().toString(),
                requestedAt = LocalDateTime.now(),
                _client = sampleClient,
                redirectUri = "https://test.org/callback",
                grantTypes = mutableSetOf(GrantType.REFRESH),
                refreshToken = tokenResponse.getRefreshToken(),
                session = ConnectSession()
            )

            handler.handleTokenRequest(request = refreshRequest, response = refreshResponse)

            refreshResponse.getAccessToken().shouldNotBeEmpty()
            refreshResponse.getAccessToken() shouldNotBe tokenResponse.getAccessToken()
            refreshResponse.getRefreshToken().shouldNotBeEmpty()
            refreshResponse.getRefreshToken() shouldNotBe tokenResponse.getRefreshToken()
        }

        scenario("""
            client with insufficient capability is rejected
        """.trimIndent()) {
            val insufficientClient = mock<CompleteClient> {
                on { id } doReturn "592473ab-6c13-4477-a1f3-e5b0345c511b"
                on { secret } doReturn "e0b327979d5641ec914e499463be1c5c"
                on { plainTextSecret() } doReturn "e0b327979d5641ec914e499463be1c5c"
                on { redirectUris } doReturn setOf("https://test.org/callback")
                on { responseTypes } doReturn setOf(ResponseType.TOKEN)
                on { grantTypes } doReturn setOf(GrantType.IMPLICIT)
                on { scopes } doReturn setOf("foo", "bar")
                on { jwksCache } doReturn clientJwks.toJson()
                on { idTokenSignedResponseAlgorithm } doReturn SigningAlgorithm.RS256
                on { idTokenEncryptedResponseAlgorithm } doReturn EncryptionAlgorithm.NONE
                on { idTokenEncryptedResponseEncoding } doReturn EncryptionEncoding.NONE
            }

            val authorizeResponse: Response = mutableMapOf()
            val authorizeRequest = ConnectAuthorizeRequest(
                id = UUID.randomUUID().toString(),
                requestedAt = LocalDateTime.now(),
                _client = insufficientClient,
                redirectUri = "https://test.org/callback",
                responseTypes = mutableSetOf(ResponseType.CODE),
                scopes = mutableSetOf("foo", "bar", OPEN_ID, OFFLINE_ACCESS),
                state = "12345678",
                nonce = "87654321",
                session = ConnectSession(
                    subject = "test-user",
                    obfuscatedSubject = "test-user-obfuscated",
                    nonce = "87654321",
                    clientId = insufficientClient.id,
                    grantedScopes = mutableSetOf("foo", OPEN_ID, OFFLINE_ACCESS),
                    finalRedirectUri = "https://test.org/callback",
                    authTime = LocalDateTime.now().minusMinutes(5)
                )
            )

            shouldThrowExactly<ConnectException> {
                handler.handleAuthorizeRequest(request = authorizeRequest, response = authorizeResponse)
            }
        }

        scenario("""
            invalid code cannot be exchanged for anything
        """.trimIndent()) {
            // authorize leg
            val authorizeResponse: Response = mutableMapOf()
            val authorizeRequest = ConnectAuthorizeRequest(
                id = UUID.randomUUID().toString(),
                requestedAt = LocalDateTime.now(),
                _client = sampleClient,
                redirectUri = "https://test.org/callback",
                responseTypes = mutableSetOf(ResponseType.CODE),
                scopes = mutableSetOf("foo", "bar", OPEN_ID, OFFLINE_ACCESS),
                state = "12345678",
                nonce = "87654321",
                session = ConnectSession(
                    subject = "test-user",
                    obfuscatedSubject = "test-user-obfuscated",
                    nonce = "87654321",
                    clientId = sampleClient.id,
                    grantedScopes = mutableSetOf("foo", OPEN_ID, OFFLINE_ACCESS),
                    finalRedirectUri = "https://test.org/callback",
                    authTime = LocalDateTime.now().minusMinutes(5)
                )
            )

            shouldNotThrowAny {
                handler.handleAuthorizeRequest(request = authorizeRequest, response = authorizeResponse)
            }

            // token leg
            val tokenResponse: Response = mutableMapOf()
            val tokenRequest = ConnectTokenRequest(
                id = UUID.randomUUID().toString(),
                requestedAt = LocalDateTime.now(),
                _client = sampleClient,
                redirectUri = "https://test.org/callback",
                code = "invalid_code",
                grantTypes = mutableSetOf(GrantType.CODE),
                session = ConnectSession()
            )

            shouldThrowExactly<ConnectException> {
                handler.handleTokenRequest(request = tokenRequest, response = tokenResponse)
            }
        }
    }

    feature("implicit flow") {
        val handler = masterHandler()

        scenario("""
            client gets access token, id token directly
        """.trimIndent()) {
            val authorizeResponse: Response = mutableMapOf()
            val authorizeRequest = ConnectAuthorizeRequest(
                id = UUID.randomUUID().toString(),
                requestedAt = LocalDateTime.now(),
                _client = sampleClient,
                redirectUri = "https://test.org/callback",
                responseTypes = mutableSetOf(ResponseType.TOKEN, ResponseType.ID_TOKEN),
                scopes = mutableSetOf("foo", "bar", OPEN_ID),
                state = "12345678",
                nonce = "87654321",
                session = ConnectSession(
                    subject = "test-user",
                    obfuscatedSubject = "test-user-obfuscated",
                    nonce = "87654321",
                    clientId = sampleClient.id,
                    grantedScopes = mutableSetOf("foo", OPEN_ID),
                    finalRedirectUri = "https://test.org/callback",
                    authTime = LocalDateTime.now().minusMinutes(5)
                )
            )

            handler.handleAuthorizeRequest(request = authorizeRequest, response = authorizeResponse)

            authorizeResponse.apply {
                getCode().shouldBeEmpty()
                getAccessToken().shouldNotBeEmpty()
                getIdToken().shouldNotBeEmpty()
            }
        }
    }

    feature("hybrid flow") {
        val handler = masterHandler()

        scenario("""
            client gets code and id token on authorize leg, and then
            exchanges code for access token and refresh token
        """.trimIndent()) {
            // authorize leg
            val authorizeResponse: Response = mutableMapOf()
            val authorizeRequest = ConnectAuthorizeRequest(
                id = UUID.randomUUID().toString(),
                requestedAt = LocalDateTime.now(),
                _client = sampleClient,
                redirectUri = "https://test.org/callback",
                responseTypes = mutableSetOf(ResponseType.CODE, ResponseType.ID_TOKEN),
                scopes = mutableSetOf("foo", "bar", OPEN_ID, OFFLINE_ACCESS),
                state = "12345678",
                nonce = "87654321",
                session = ConnectSession(
                    subject = "test-user",
                    obfuscatedSubject = "test-user-obfuscated",
                    nonce = "87654321",
                    clientId = sampleClient.id,
                    grantedScopes = mutableSetOf("foo", OPEN_ID, OFFLINE_ACCESS),
                    finalRedirectUri = "https://test.org/callback",
                    authTime = LocalDateTime.now().minusMinutes(5)
                )
            )

            handler.handleAuthorizeRequest(request = authorizeRequest, response = authorizeResponse)

            val code = authorizeResponse.getCode()
            code.shouldNotBeEmpty()
            authorizeResponse.getIdToken().shouldNotBeEmpty()

            // token leg
            val tokenResponse: Response = mutableMapOf()
            val tokenRequest = ConnectTokenRequest(
                id = UUID.randomUUID().toString(),
                requestedAt = LocalDateTime.now(),
                _client = sampleClient,
                redirectUri = "https://test.org/callback",
                code = code,
                grantTypes = mutableSetOf(GrantType.CODE),
                session = ConnectSession()
            )

            handler.handleTokenRequest(request = tokenRequest, response = tokenResponse)

            tokenResponse.getAccessToken().shouldNotBeEmpty()
            tokenResponse.getRefreshToken().shouldNotBeEmpty()
            tokenResponse.getTokenType() shouldBe "Bearer"
            tokenResponse.getExpiresIn() shouldBeGreaterThan 0
        }
    }

    feature("client credentials flow") {

        val handler = masterHandler()

        scenario("client exchanges credentials for access token and refresh token") {
            val tokenResponse: Response = mutableMapOf()
            val tokenRequest = ConnectTokenRequest(
                id = UUID.randomUUID().toString(),
                requestedAt = LocalDateTime.now(),
                _client = sampleClient,
                redirectUri = "https://test.org/callback",
                grantTypes = mutableSetOf(GrantType.CLIENT),
                session = ConnectSession(),
                scopes = mutableSetOf("foo", OFFLINE_ACCESS)
            )

            handler.handleTokenRequest(request = tokenRequest, response = tokenResponse)

            tokenResponse.getAccessToken().shouldNotBeEmpty()
            tokenResponse.getRefreshToken().shouldNotBeEmpty()
            tokenResponse.getTokenType() shouldBe "Bearer"
            tokenResponse.getExpiresIn() shouldBeGreaterThan 0
        }
    }

}) {
    companion object {

        private val masterRepo = MemoryAuthorizeCodeRepo()

        private val authorizeCodeHelper = AuthorizeCodeHelper(
            strategy = HmacAuthorizeCodeStrategy(
                signingAlgorithm = SigningAlgorithm.HS256,
                key = AesKey("df36fc3665814870a076d038c8ff4a0f".toByteArray(StandardCharsets.UTF_8)),
                entropy = 32
            ),
            repository = masterRepo
        )

        private val accessTokenHelper = AccessTokenHelper(
            strategy = JwtAccessTokenStrategy(
                signingAlgorithm = SigningAlgorithm.RS256,
                jwks = JsonWebKeySet(
                    RsaJwkGenerator.generateJwk(2048).apply {
                        use = Use.SIGNATURE
                        keyId = "test_key"
                        algorithm = SigningAlgorithm.RS256.value
                    }
                ),
                issuerUrl = "https://test.org",
                lifespan = Duration.ofMinutes(30)
            ),
            repository = MemoryAccessTokenRepo(),
            lifespan = Duration.ofMinutes(30)
        )

        private val refreshTokenHelper = RefreshTokenHelper(
            strategy = HmacRefreshTokenStrategy(
                signingAlgorithm = SigningAlgorithm.HS256,
                key = AesKey("df36fc3665814870a076d038c8ff4a0f".toByteArray(StandardCharsets.UTF_8)),
                entropy = 32
            ),
            repository = MemoryRefreshTokenRepo()
        )

        private val idTokenHelper = IdTokenHelper(
            strategy = JwxIdTokenStrategy(
                lifespan = Duration.ofDays(1),
                signingAlgorithm = SigningAlgorithm.RS256,
                issuerUrl = "https://test.org",
                jwks = JsonWebKeySet(
                    RsaJwkGenerator.generateJwk(2048).apply {
                        keyId = "server-test-key"
                        use = Use.SIGNATURE
                        algorithm = SigningAlgorithm.RS256.value
                    }
                )
            )
        )

        private val authorizeCodeFlowHandler = AuthorizeCodeFlowHandler(
            authorizeCodeHelper = authorizeCodeHelper,
            accessTokenHelper = accessTokenHelper,
            refreshTokenHelper = refreshTokenHelper,
            idTokenHelper = idTokenHelper
        )

        private val hybridFlowHandler = HybridFlowHandler(
            idTokenHelper = idTokenHelper,
            accessTokenHelper = accessTokenHelper,
            authorizeCodeHelper = authorizeCodeHelper
        )

        private val implicitFlowHandler = ImplicitFlowHandler(
            accessTokenHelper = accessTokenHelper,
            idTokenHelper = idTokenHelper
        )

        private val clientCredentialsFlowHandler = ClientCredentialsFlowHandler(
            accessTokenHelper = accessTokenHelper,
            refreshTokenHelper = refreshTokenHelper
        )

        private val refreshFlowHandler = RefreshFlowHandler(
            accessTokenHelper = accessTokenHelper,
            refreshTokenHelper = refreshTokenHelper,
            idTokenHelper = idTokenHelper
        )

        val masterHandler = {
            ConnectHandler(
                authorizeHandlers = listOf(
                    authorizeCodeFlowHandler,
                    hybridFlowHandler,
                    implicitFlowHandler
                ),
                tokenHandlers = listOf(
                    authorizeCodeFlowHandler,
                    clientCredentialsFlowHandler,
                    refreshFlowHandler
                )
            )
        }

        interface CompleteClient: Client, ClientSecretAware, JwksCacheAware
        val clientJwks = JsonWebKeySet(
            RsaJwkGenerator.generateJwk(2048).apply {
                keyId = "client-test-key"
                use = Use.SIGNATURE
                algorithm = SigningAlgorithm.RS256.value
            }
        )
        val sampleClient = mock<CompleteClient> {
            on { id } doReturn "592473ab-6c13-4477-a1f3-e5b0345c511b"
            on { secret } doReturn "e0b327979d5641ec914e499463be1c5c"
            on { plainTextSecret() } doReturn "e0b327979d5641ec914e499463be1c5c"
            on { type } doReturn ClientType.CONFIDENTIAL
            on { redirectUris } doReturn setOf("https://test.org/callback")
            on { responseTypes } doReturn setOf(ResponseType.CODE, ResponseType.TOKEN, ResponseType.ID_TOKEN)
            on { grantTypes } doReturn setOf(GrantType.CODE, GrantType.IMPLICIT, GrantType.CLIENT, GrantType.REFRESH)
            on { scopes } doReturn setOf("foo", "bar", OFFLINE_ACCESS, OPEN_ID)
            on { jwksCache } doReturn clientJwks.toJson()
            on { idTokenSignedResponseAlgorithm } doReturn SigningAlgorithm.RS256
            on { idTokenEncryptedResponseAlgorithm } doReturn EncryptionAlgorithm.NONE
            on { idTokenEncryptedResponseEncoding } doReturn EncryptionEncoding.NONE
        }

        private class MemoryAuthorizeCodeRepo(
            private val db: MutableMap<String, Session> = mutableMapOf()
        ) : AuthorizeCodeRepository {
            override suspend fun getSession(code: String): Session =
                db.getOrElse(code) { throw Errors.invalidGrant("authorize code is not found") }
            override suspend fun save(code: String, session: Session) {
                db[code] = session
            }
            override suspend fun delete(code: String) {
                db.remove(code)
            }
        }

        private class MemoryAccessTokenRepo(
            private val dbByToken: MutableMap<String, Session> = mutableMapOf(),
            private val dbByRequestId: MutableMap<String, Session> = mutableMapOf()
        ) : AccessTokenRepository {
            override suspend fun getSession(token: String): Session = dbByToken.getOrElse(token) {
                throw Errors.invalidGrant("access token is not found")
            }
            override suspend fun save(token: String, session: Session) {
                dbByToken[token] = session
                dbByToken[session.savedByRequestId] = session
            }

            override suspend fun delete(token: String) {
                dbByRequestId.remove(dbByToken[token]?.savedByRequestId)
                dbByToken.remove(token)
            }
            override suspend fun deleteByRequestId(requestId: String) {
                // technically incorrect implementation, but it does not harm our test purpose.
                dbByRequestId.remove(requestId)
            }
        }

        private class MemoryRefreshTokenRepo(
            private val dbByToken: MutableMap<String, Session> = mutableMapOf(),
            private val dbByRequestId: MutableMap<String, Session> = mutableMapOf()
        ) : RefreshTokenRepository {
            override suspend fun getSession(token: String): Session = dbByToken.getOrElse(token) {
                throw Errors.invalidGrant("refresh token is not found")
            }
            override suspend fun save(token: String, session: Session) {
                dbByToken[token] = session
                dbByToken[session.savedByRequestId] = session
            }
            override suspend fun delete(token: String) {
                dbByRequestId.remove(dbByToken[token]?.savedByRequestId)
                dbByToken.remove(token)
            }
            override suspend fun deleteByRequestId(requestId: String) {
                // technically incorrect implementation, but it does not harm our test purpose.
                dbByRequestId.remove(requestId)
            }
        }
    }
}