package io.imulab.connect

import com.nhaarman.mockitokotlin2.anyOrNull
import com.nhaarman.mockitokotlin2.doAnswer
import com.nhaarman.mockitokotlin2.doReturn
import com.nhaarman.mockitokotlin2.mock
import io.imulab.connect.auth.*
import io.imulab.connect.client.*
import io.imulab.connect.spi.HttpRequest
import io.kotlintest.matchers.types.shouldBeTypeOf
import io.kotlintest.matchers.types.shouldNotBeTypeOf
import io.kotlintest.shouldThrowExactly
import io.kotlintest.specs.FeatureSpec
import org.jose4j.jwk.JsonWebKeySet
import org.jose4j.jwk.RsaJwkGenerator
import org.jose4j.jwk.Use
import org.jose4j.jws.JsonWebSignature
import org.jose4j.jwt.JwtClaims
import org.jose4j.keys.AesKey
import java.util.*

class AuthenticationTest : FeatureSpec({

    feature("basic authentication") {
        scenario("correct credentials shall pass") {
            val httpRequest = mock<HttpRequest> {
                on { method() } doReturn "POST"
                on { header(anyOrNull()) } doAnswer { ic ->
                    when (ic.arguments[0].toString()) {
                        "Authorization" -> {
                            val b64 = Base64.getEncoder().withoutPadding()
                            val raw = "${basicClient.id}:${basicClient.plainTextSecret()}"
                            "Basic ${b64.encodeToString(raw.toByteArray())}"
                        }
                        else -> ""
                    }
                }
                onBlocking { parameter(anyOrNull()) } doReturn ""
            }
            val req = ConnectTokenRequest()

            authHandler.authenticate(httpRequest, req)

            req.client.shouldNotBeTypeOf<NothingClient>()
        }

        scenario("incorrect credentials shall be rejected") {
            val httpRequest = mock<HttpRequest> {
                on { method() } doReturn "POST"
                on { header(anyOrNull()) } doAnswer { ic ->
                    when (ic.arguments[0].toString()) {
                        "Authorization" -> {
                            val b64 = Base64.getEncoder().withoutPadding()
                            val raw = "${basicClient.id}:foobar"
                            "Basic ${b64.encodeToString(raw.toByteArray())}"
                        }
                        else -> ""
                    }
                }
                onBlocking { parameter(anyOrNull()) } doReturn ""
            }
            val req = ConnectTokenRequest()

            shouldThrowExactly<ConnectException> {
                authHandler.authenticate(httpRequest, req)
            }
            req.client.shouldBeTypeOf<NothingClient>()
        }
    }

    feature("post authentication") {
        scenario("correct credentials shall pass") {
            val httpRequest = mock<HttpRequest> {
                on { method() } doReturn "POST"
                on { header(anyOrNull()) } doAnswer { ic ->
                    when (ic.arguments[0].toString()) {
                        "Content-Type" -> "application/x-www-form-urlencoded"
                        else -> ""
                    }
                }
                onBlocking { parameter(anyOrNull()) } doAnswer { ic ->
                    when (ic.arguments[0].toString()) {
                        "client_id" -> postClient.id
                        "client_secret" -> postClient.secret
                        else -> ""
                    }
                }
            }
            val req = ConnectTokenRequest()

            authHandler.authenticate(httpRequest, req)

            req.client.shouldNotBeTypeOf<NothingClient>()
        }

        scenario("incorrect credentials shall be rejected") {
            val httpRequest = mock<HttpRequest> {
                on { method() } doReturn "POST"
                on { header(anyOrNull()) } doAnswer { ic ->
                    when (ic.arguments[0].toString()) {
                        "Content-Type" -> "application/x-www-form-urlencoded"
                        else -> ""
                    }
                }
                onBlocking { parameter(anyOrNull()) } doAnswer { ic ->
                    when (ic.arguments[0].toString()) {
                        "client_id" -> postClient.id
                        "client_secret" -> "foobar"
                        else -> ""
                    }
                }
            }
            val req = ConnectTokenRequest()

            shouldThrowExactly<ConnectException> {
                authHandler.authenticate(httpRequest, req)
            }
            req.client.shouldBeTypeOf<NothingClient>()
        }
    }

    feature("client secret jwt authentication") {
        scenario("correct credentials shall pass") {
            val assertion = JsonWebSignature().apply {
                algorithmHeaderValue = SigningAlgorithm.HS256.value
                key = AesKey(clientSecretJwtClient.plainTextSecret().toByteArray())
                payload = JwtClaims().also { c ->
                    c.setGeneratedJwtId()
                    c.setIssuedAtToNow()
                    c.setNotBeforeMinutesInThePast(0f)
                    c.setExpirationTimeMinutesInTheFuture(60f)
                    c.issuer = clientSecretJwtClient.id
                    c.subject = clientSecretJwtClient.id
                    c.setAudience("https://test.org/oauth/token")
                }.toJson()
            }.compactSerialization
            val httpRequest = mock<HttpRequest> {
                on { method() } doReturn "POST"
                on { header(anyOrNull()) } doAnswer { ic ->
                    when (ic.arguments[0].toString()) {
                        "Content-Type" -> "application/x-www-form-urlencoded"
                        else -> ""
                    }
                }
                onBlocking { parameter(anyOrNull()) } doAnswer { ic ->
                    when (ic.arguments[0].toString()) {
                        "client_id" -> clientSecretJwtClient.id
                        "client_assertion" -> assertion
                        "client_assertion_type" -> CLIENT_ASSERTION_JWT_BEARER
                        else -> ""
                    }
                }
            }
            val req = ConnectTokenRequest()

            authHandler.authenticate(httpRequest, req)

            req.client.shouldNotBeTypeOf<NothingClient>()
        }

        scenario("incorrect credentials shall be rejected") {
            val assertion = JsonWebSignature().apply {
                algorithmHeaderValue = SigningAlgorithm.HS256.value
                key = AesKey("--E77AF9DFA07A44A083324271BAB8F4DB--".toByteArray())
                payload = JwtClaims().also { c ->
                    c.setGeneratedJwtId()
                    c.setIssuedAtToNow()
                    c.setNotBeforeMinutesInThePast(0f)
                    c.setExpirationTimeMinutesInTheFuture(60f)
                    c.issuer = clientSecretJwtClient.id
                    c.subject = clientSecretJwtClient.id
                    c.setAudience("https://test.org/oauth/token")
                }.toJson()
            }.compactSerialization
            val httpRequest = mock<HttpRequest> {
                on { method() } doReturn "POST"
                on { header(anyOrNull()) } doAnswer { ic ->
                    when (ic.arguments[0].toString()) {
                        "Content-Type" -> "application/x-www-form-urlencoded"
                        else -> ""
                    }
                }
                onBlocking { parameter(anyOrNull()) } doAnswer { ic ->
                    when (ic.arguments[0].toString()) {
                        "client_id" -> clientSecretJwtClient.id
                        "client_assertion" -> assertion
                        "client_assertion_type" -> CLIENT_ASSERTION_JWT_BEARER
                        else -> ""
                    }
                }
            }
            val req = ConnectTokenRequest()

            shouldThrowExactly<ConnectException> {
                authHandler.authenticate(httpRequest, req)
            }
            req.client.shouldBeTypeOf<NothingClient>()
        }
    }

    feature("private key jwt authentication") {
        scenario("correct credentials shall pass") {
            val assertion = JsonWebSignature().apply {
                algorithmHeaderValue = SigningAlgorithm.RS256.value
                key = clientJwks.jsonWebKeys[0].resolvePrivateKey()
                keyIdHeaderValue = clientJwks.jsonWebKeys[0].keyId
                payload = JwtClaims().also { c ->
                    c.setGeneratedJwtId()
                    c.setIssuedAtToNow()
                    c.setNotBeforeMinutesInThePast(0f)
                    c.setExpirationTimeMinutesInTheFuture(60f)
                    c.issuer = privateKeyJwtClient.id
                    c.subject = privateKeyJwtClient.id
                    c.setAudience("https://test.org/oauth/token")
                }.toJson()
            }.compactSerialization
            val httpRequest = mock<HttpRequest> {
                on { method() } doReturn "POST"
                on { header(anyOrNull()) } doAnswer { ic ->
                    when (ic.arguments[0].toString()) {
                        "Content-Type" -> "application/x-www-form-urlencoded"
                        else -> ""
                    }
                }
                onBlocking { parameter(anyOrNull()) } doAnswer { ic ->
                    when (ic.arguments[0].toString()) {
                        "client_id" -> privateKeyJwtClient.id
                        "client_assertion" -> assertion
                        "client_assertion_type" -> CLIENT_ASSERTION_JWT_BEARER
                        else -> ""
                    }
                }
            }
            val req = ConnectTokenRequest()

            authHandler.authenticate(httpRequest, req)

            req.client.shouldNotBeTypeOf<NothingClient>()
        }

        scenario("incorrect credentials shall be rejected") {
            val jwk = RsaJwkGenerator.generateJwk(2048).apply {
                keyId = "incorrect-key"
                use = Use.SIGNATURE
                algorithm = SigningAlgorithm.RS256.value
            }
            val assertion = JsonWebSignature().apply {
                algorithmHeaderValue = SigningAlgorithm.RS256.value
                key = jwk.resolvePrivateKey()
                keyIdHeaderValue = jwk.keyId
                payload = JwtClaims().also { c ->
                    c.setGeneratedJwtId()
                    c.setIssuedAtToNow()
                    c.setNotBeforeMinutesInThePast(0f)
                    c.setExpirationTimeMinutesInTheFuture(60f)
                    c.issuer = privateKeyJwtClient.id
                    c.subject = privateKeyJwtClient.id
                    c.setAudience("https://test.org/oauth/token")
                }.toJson()
            }.compactSerialization
            val httpRequest = mock<HttpRequest> {
                on { method() } doReturn "POST"
                on { header(anyOrNull()) } doAnswer { ic ->
                    when (ic.arguments[0].toString()) {
                        "Content-Type" -> "application/x-www-form-urlencoded"
                        else -> ""
                    }
                }
                onBlocking { parameter(anyOrNull()) } doAnswer { ic ->
                    when (ic.arguments[0].toString()) {
                        "client_id" -> privateKeyJwtClient.id
                        "client_assertion" -> assertion
                        "client_assertion_type" -> CLIENT_ASSERTION_JWT_BEARER
                        else -> ""
                    }
                }
            }
            val req = ConnectTokenRequest()

            shouldThrowExactly<ConnectException> {
                authHandler.authenticate(httpRequest, req)
            }
            req.client.shouldBeTypeOf<NothingClient>()
        }
    }

    feature("none authentication") {
        scenario("public client shall pass") {

        }

        scenario("non-public shall be rejected") {

        }
    }

}) {
    companion object {
        interface CompleteClient: Client, ClientSecretAware, JwksCacheAware

        val clientJwks = JsonWebKeySet(
            RsaJwkGenerator.generateJwk(2048).apply {
                keyId = "client-test-key"
                use = Use.SIGNATURE
                algorithm = SigningAlgorithm.RS256.value
            }
        )

        val basicClient = mock<CompleteClient> {
            on { id } doReturn "4dd6bd0c-e0b9-4136-9435-15b478f7258e"
            on { secret } doReturn "e0b327979d5641ec914e499463be1c5c"
            on { plainTextSecret() } doReturn "e0b327979d5641ec914e499463be1c5c"
            on { jwksCache } doReturn clientJwks.toJson()
            on { tokenEndpointAuthMethod } doReturn AuthenticationMethod.BASIC
        }

        val postClient = mock<CompleteClient> {
            on { id } doReturn "e1691c50-93c5-49f6-aa4e-12654775c343"
            on { secret } doReturn "e0b327979d5641ec914e499463be1c5c"
            on { plainTextSecret() } doReturn "e0b327979d5641ec914e499463be1c5c"
            on { jwksCache } doReturn clientJwks.toJson()
            on { tokenEndpointAuthMethod } doReturn AuthenticationMethod.POST
        }

        val clientSecretJwtClient = mock<CompleteClient> {
            on { id } doReturn "d0e253aa-b096-4976-88a2-15b3b4e3c69b"
            on { secret } doReturn "e0b327979d5641ec914e499463be1c5c"
            on { plainTextSecret() } doReturn "e0b327979d5641ec914e499463be1c5c"
            on { jwksCache } doReturn clientJwks.toJson()
            on { tokenEndpointAuthMethod } doReturn AuthenticationMethod.JWT_SECRET
            on { tokenEndpointAuthSigningAlgorithm } doReturn SigningAlgorithm.HS256
        }

        val privateKeyJwtClient = mock<CompleteClient> {
            on { id } doReturn "458b69db-5596-40b2-80f9-8ac08763e464"
            on { secret } doReturn "e0b327979d5641ec914e499463be1c5c"
            on { plainTextSecret() } doReturn "e0b327979d5641ec914e499463be1c5c"
            on { jwksCache } doReturn clientJwks.toJson()
            on { tokenEndpointAuthMethod } doReturn AuthenticationMethod.JWT_PRIVATE
            on { tokenEndpointAuthSigningAlgorithm } doReturn SigningAlgorithm.RS256
        }

        private val clientLookup = mock<ClientLookup> {
            onBlocking { findById(anyOrNull()) } doAnswer { ic ->
                when (ic.arguments[0].toString()) {
                    basicClient.id -> basicClient
                    postClient.id -> postClient
                    clientSecretJwtClient.id -> clientSecretJwtClient
                    privateKeyJwtClient.id -> privateKeyJwtClient
                    else -> throw Errors.clientNotFound(ic.arguments[0].toString())
                }
            }
        }

        private val basicAuthenticator = ClientSecretBasicAuthenticator(clientLookup = clientLookup)

        private val postAuthenticator = ClientSecretPostAuthenticator(clientLookup = clientLookup)

        private val jwtAuthenticator = ClientJwtAuthenticator(
            clientLookup = clientLookup,
            tokenEndpointUrl = "https://test.org/oauth/token"
        )

        private val noneAuthenticator = NoneAuthenticator(clientLookup = clientLookup)

        val authHandler = AuthenticationHandler(
            authenticators = listOf(
                basicAuthenticator,
                postAuthenticator,
                jwtAuthenticator
            ),
            noneAuthenticator = noneAuthenticator
        )
    }
}