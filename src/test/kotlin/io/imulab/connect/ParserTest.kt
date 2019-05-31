package io.imulab.connect

import com.nhaarman.mockitokotlin2.anyOrNull
import com.nhaarman.mockitokotlin2.doAnswer
import com.nhaarman.mockitokotlin2.doReturn
import com.nhaarman.mockitokotlin2.mock
import io.imulab.connect.client.*
import io.imulab.connect.parse.*
import io.imulab.connect.spi.HttpRequest
import io.kotlintest.matchers.collections.shouldContainExactly
import io.kotlintest.matchers.string.shouldNotBeEmpty
import io.kotlintest.shouldBe
import io.kotlintest.shouldNotThrowAny
import io.kotlintest.specs.FeatureSpec
import org.jose4j.jwe.JsonWebEncryption
import org.jose4j.jwk.JsonWebKeySet
import org.jose4j.jwk.RsaJwkGenerator
import org.jose4j.jwk.Use
import org.jose4j.jws.JsonWebSignature
import org.jose4j.jwt.JwtClaims

class ParserTest : FeatureSpec({

    feature("resolve authorize request parameters") {
        scenario("resolve merely from http request (with default)") {
            val httpRequest = mock<HttpRequest> {
                on { method() } doReturn "GET"
                on { header(anyOrNull()) } doReturn ""
                on { parameter(anyOrNull()) } doAnswer { ic ->
                    when (ic.arguments[0].toString()) {
                        "client_id" -> sampleClient.id
                        "response_type" -> "code"
                        "redirect_uri" -> "https://test.org/callback"
                        "scope" -> "foo"
                        "state" -> "12345678"
                        "prompt" -> "none"
                        "nonce" -> "87654321"
                        else -> ""
                    }
                }
            }
            val request = ConnectAuthorizeRequest()

            shouldNotThrowAny {
                clientDetailsParser.parse(httpRequest, request)
                simpleParameterParser.parse(httpRequest, request)
                defaultValueParser.parse(httpRequest, request)
                validatingParser.parse(httpRequest, request)
            }
            request.apply {
                id.shouldNotBeEmpty()
                client.id shouldBe sampleClient.id
                responseTypes shouldContainExactly mutableSetOf(ResponseType.CODE)
                redirectUri shouldBe "https://test.org/callback"
                scopes shouldContainExactly mutableSetOf("foo")
                state shouldBe "12345678"
                nonce shouldBe "87654321"
                prompt shouldContainExactly mutableSetOf(Prompt.NONE)
                session.apply {
                    clientId shouldBe sampleClient.id
                    nonce shouldBe "87654321"
                    finalRedirectUri shouldBe "https://test.org/callback"
                }
            }
        }

        scenario("resolve from http request and request_uri parameter (with default)") {
            val httpRequest = mock<HttpRequest> {
                on { method() } doReturn "GET"
                on { header(anyOrNull()) } doReturn ""
                on { parameter(anyOrNull()) } doAnswer { ic ->
                    when (ic.arguments[0].toString()) {
                        "client_id" -> sampleClient.id
                        "response_type" -> "code"
                        "redirect_uri" -> "https://test.org/callback"
                        "scope" -> "foo"
                        "state" -> "12345678"
                        "prompt" -> "none"
                        "nonce" -> "87654321"
                        "request_uri" -> "https://test.org/request.txt"
                        else -> ""
                    }
                }
            }
            val request = ConnectAuthorizeRequest()

            shouldNotThrowAny {
                clientDetailsParser.parse(httpRequest, request)
                simpleParameterParser.parse(httpRequest, request)
                requestOrUriParser.parse(httpRequest, request)
                defaultValueParser.parse(httpRequest, request)
                validatingParser.parse(httpRequest, request)
            }
            request.apply {
                id.shouldNotBeEmpty()
                client.id shouldBe sampleClient.id
                responseTypes shouldContainExactly mutableSetOf(ResponseType.CODE, ResponseType.TOKEN)
                redirectUri shouldBe "https://test.org/callback2"
                scopes shouldContainExactly mutableSetOf("foo", OPEN_ID)
                state shouldBe "12345678"
                nonce shouldBe "87654321"
                prompt shouldContainExactly mutableSetOf(Prompt.NONE)
                session.apply {
                    clientId shouldBe sampleClient.id
                    nonce shouldBe "87654321"
                    finalRedirectUri shouldBe "https://test.org/callback2"
                }
            }
        }
    }

    feature("resolve token request parameters") {
        scenario("resolve from http request (with default)") {
            val httpRequest = mock<HttpRequest> {
                on { method() } doReturn "GET"
                on { header(anyOrNull()) } doReturn ""
                on { parameter(anyOrNull()) } doAnswer { ic ->
                    when (ic.arguments[0].toString()) {
                        "client_id" -> sampleClient.id
                        "grant_type" -> "authorization_code"
                        "redirect_uri" -> "https://test.org/callback"
                        "scope" -> "foo bar"
                        "code" -> "some-authorize-code"
                        else -> ""
                    }
                }
            }
            val request = ConnectTokenRequest()

            shouldNotThrowAny {
                simpleParameterParser.parse(httpRequest, request)
                defaultValueParser.parse(httpRequest, request)
                validatingParser.parse(httpRequest, request)
            }
            request.apply {
                id.shouldNotBeEmpty()
                client.id shouldBe sampleClient.id
                grantTypes shouldContainExactly setOf(GrantType.CODE)
                redirectUri shouldBe "https://test.org/callback"
                scopes shouldContainExactly setOf("foo", "bar")
                code shouldBe "some-authorize-code"
            }
        }
    }

}) {
    companion object {
        private interface CompleteClient : Client, ClientSecretAware, JwksCacheAware, RequestCacheAware

        private const val issuerUrl = "https://test.org"

        private val serverJwks = JsonWebKeySet(
            RsaJwkGenerator.generateJwk(2048).apply {
                keyId = "server-encryption-key"
                use = Use.ENCRYPTION
                algorithm = EncryptionAlgorithm.RSA1_5.value
            }
        )

        private val jwks = JsonWebKeySet(
            RsaJwkGenerator.generateJwk(2048).apply {
                keyId = "my-signing-key"
                use = Use.SIGNATURE
                algorithm = SigningAlgorithm.RS256.value
            }
        )

        private val sampleClient: CompleteClient = mock {
            on { id } doReturn "5adb2289-b448-4994-849a-3aed1efeb211"
            on { type } doReturn ClientType.CONFIDENTIAL
            on { redirectUris } doReturn setOf("https://test.org/callback", "https://test.org/callback2")
            on { responseTypes } doReturn setOf(ResponseType.CODE, ResponseType.TOKEN)
            on { grantTypes } doReturn setOf(GrantType.CODE)
            on { scopes } doReturn setOf("foo", "bar", OPEN_ID)
            on { jwksCache } doReturn jwks.toJson()
            on { requestObjectSigningAlgorithm } doReturn SigningAlgorithm.RS256
            on { requestObjectEncryptionAlgorithm } doReturn EncryptionAlgorithm.RSA1_5
            on { requestObjectEncryptionEncoding } doReturn EncryptionEncoding.AES_128_GCM
            on { requestUris } doReturn setOf("https://test.org/request.txt")
            on { uriForRequestCache(anyOrNull()) } doAnswer { ic ->
                when (ic.arguments[0].toString()) {
                    "https://test.org/request.txt" -> request
                    else -> ""
                }
            }
        }

        private val clientLookup = mock<ClientLookup> {
            onBlocking { findById(anyOrNull()) } doAnswer { ic ->
                when(ic.arguments[0].toString()) {
                    sampleClient.id -> sampleClient
                    else -> throw Errors.clientNotFound(ic.arguments[0].toString())
                }
            }
        }

        private val request = JwtClaims().apply {
            setGeneratedJwtId()
            setIssuedAtToNow()
            issuer = sampleClient.id
            subject = sampleClient.id
            setAudience(issuerUrl)
            setClaim("response_type", "code token")
            setClaim("redirect_uri", "https://test.org/callback2")
            setClaim("scope", "foo openid")
        }.let { c ->
            JsonWebSignature().apply {
                keyIdHeaderValue = jwks.jsonWebKeys[0].keyId
                algorithmHeaderValue = SigningAlgorithm.RS256.value
                key = jwks.jsonWebKeys[0].resolvePrivateKey()
                payload = c.toJson()
            }.compactSerialization
        }.let { raw ->
            JsonWebEncryption().apply {
                setPlaintext(raw)
                algorithmHeaderValue = EncryptionAlgorithm.RSA1_5.value
                encryptionMethodHeaderParameter = EncryptionEncoding.AES_128_GCM.value
                key = serverJwks.jsonWebKeys[0].resolvePublicKey()
            }.compactSerialization
        }

        val clientDetailsParser = ClientDetailsParser(
            clientLookup = clientLookup,
            mergeBackHard = true
        )

        val simpleParameterParser = SimpleParameterParser(
            clientLookup = clientLookup,
            jsonProvider = mock(),
            mergeBackHard = true
        )

        val requestOrUriParser = RequestOrUriParser(
            clientLookup = clientLookup,
            issuerUrl = issuerUrl,
            serverJwks = serverJwks,
            httpClient = mock(),
            requestParameterSupported = true,
            requestUriParameterSupported = true,
            requireRequestUriRegistration = true,
            mergeBackHard = true
        )

        val defaultValueParser = DefaultValueParser()

        val validatingParser = ValidatingParser()
    }
}