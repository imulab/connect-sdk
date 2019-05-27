package io.imulab.connect

import com.nhaarman.mockitokotlin2.doReturn
import com.nhaarman.mockitokotlin2.mock
import io.imulab.connect.client.*
import io.kotlintest.matchers.string.shouldNotBeEmpty
import io.kotlintest.specs.FeatureSpec
import org.jose4j.jwa.AlgorithmConstraints
import org.jose4j.jwe.JsonWebEncryption
import org.jose4j.jwk.JsonWebKey
import org.jose4j.jwk.JsonWebKeySet
import org.jose4j.jwk.RsaJwkGenerator
import org.jose4j.jwk.Use
import org.jose4j.jwt.consumer.JwtConsumerBuilder
import java.time.Duration
import java.time.LocalDateTime

class IdTokenTest : FeatureSpec({

    feature("decode id token") {
        scenario("decode a signed id_token") {
            val response: Response = mutableMapOf()
            val request = ConnectTokenRequest(
                client = signWithJwksClient,
                session = sampleSession().apply {
                    clientId = signWithJwksClient.id
                }
            )
            helper.issueToken(request, response)
            val idToken = response.getIdToken()

            val claims = strategy.decodeToken(idToken, request)
            claims.jwtId.shouldNotBeEmpty()
            claims.subject.shouldNotBeEmpty()
        }

        scenario("client re-encrypts the id_token and send it back (id_token_hint)") {
            val response: Response = mutableMapOf()
            val request = ConnectTokenRequest(
                client = signAndEncryptClient,
                session = sampleSession().apply {
                    clientId = signAndEncryptClient.id
                }
            )

            helper.issueToken(request, response)
            val idToken = response.getIdToken()

            // here we simulate the process where client decrypts the token and re-encrypt it with
            // a key known to the server so server can decrypt it again.
            val jwt = JsonWebEncryption().apply {
                setAlgorithmConstraints(
                    AlgorithmConstraints(AlgorithmConstraints.ConstraintType.WHITELIST,
                        signAndEncryptClient.idTokenEncryptedResponseAlgorithm.value
                    ))
                setContentEncryptionAlgorithmConstraints(
                    AlgorithmConstraints(AlgorithmConstraints.ConstraintType.WHITELIST,
                        signAndEncryptClient.idTokenEncryptedResponseEncoding.value
                    ))
                compactSerialization = idToken
                key = signAndEncryptClient.resolveJwks()
                    .selectKeyForEncryption(signAndEncryptClient.idTokenEncryptedResponseAlgorithm)
                    .resolvePrivateKey()
            }.plaintextString
            val newJwk = serverJwks.selectKeyForEncryption(EncryptionAlgorithm.RSA1_5)
            val newJwe = JsonWebEncryption().also { jwe ->
                jwe.setPlaintext(jwt)
                jwe.contentTypeHeaderValue = "JWT"
                jwe.algorithmHeaderValue = newJwk.algorithm
                jwe.encryptionMethodHeaderParameter = signAndEncryptClient.idTokenEncryptedResponseEncoding.value
                jwe.key = newJwk.resolvePublicKey()
                jwe.keyIdHeaderValue = newJwk.keyId
            }.compactSerialization

            // now we ask the server to decode the re-encrypted token
            val claims = strategy.decodeToken(newJwe, request)

            claims.jwtId.shouldNotBeEmpty()
            claims.subject.shouldNotBeEmpty()
        }
    }

    feature("generate id token") {
        scenario("generate for client requesting symmetric signing with secret") {
            val response: Response = mutableMapOf()
            val request = ConnectTokenRequest(
                client = signWithSecretClient,
                session = sampleSession().apply {
                    clientId = signWithSecretClient.id
                }
            )

            helper.issueToken(request, response)

            response.getIdToken().shouldNotBeEmpty()
        }

        scenario("generate for client requesting asymmetric signing with server jwks") {
            val response: Response = mutableMapOf()
            val request = ConnectTokenRequest(
                client = signWithJwksClient,
                session = sampleSession().apply {
                    clientId = signWithJwksClient.id
                }
            )

            helper.issueToken(request, response)

            response.getIdToken().shouldNotBeEmpty()
        }

        scenario("generate for client requesting signing and encryption") {
            val response: Response = mutableMapOf()
            val request = ConnectTokenRequest(
                client = signAndEncryptClient,
                session = sampleSession().apply {
                    clientId = signAndEncryptClient.id
                }
            )

            helper.issueToken(request, response)

            response.getIdToken().shouldNotBeEmpty()
        }

        scenario("generate for client requesting only encryption") {
            val response: Response = mutableMapOf()
            val request = ConnectTokenRequest(
                client = encryptOnlyClient,
                session = sampleSession().apply {
                    clientId = encryptOnlyClient.id
                }
            )

            helper.issueToken(request, response)

            response.getIdToken().shouldNotBeEmpty()
        }

        scenario("access token hash and/or code hash is included") {
            val response: Response = mutableMapOf()
            val request = ConnectTokenRequest(
                client = signWithSecretClient,
                session = sampleSession().apply {
                    clientId = signWithSecretClient.id
                }
            )

            helper.issueToken(request, response.apply {
                setCode("code")
                setAccessToken("access_token")
            })
            val claims = JwtConsumerBuilder().apply {
                setDisableRequireSignature()
                setSkipAllValidators()
                setSkipSignatureVerification()
            }.build().processToClaims(response.getIdToken())

            claims.safeString("at_hash").shouldNotBeEmpty()
            claims.safeString("c_hash").shouldNotBeEmpty()
        }
    }
}) {

    interface JwksAwareClient : Client, JwksCacheAware

    companion object {
        val signWithSecretClient = mock<AccessTokenTest.Companion.SecretAwareClient> {
            on { id } doReturn "4a1f3d25-7f55-498d-93e3-430fa0429a10"
            on { secret } doReturn "ff2b986a7a324b548d31f4673430706d"
            on { plainTextSecret() } doReturn "ff2b986a7a324b548d31f4673430706d"
            on { idTokenSignedResponseAlgorithm } doReturn SigningAlgorithm.HS256
            on { idTokenEncryptedResponseAlgorithm } doReturn EncryptionAlgorithm.NONE
            on { idTokenEncryptedResponseEncoding } doReturn  EncryptionEncoding.NONE
        }

        val signWithJwksClient = mock<Client> {
            on { id } doReturn "3b02da69-21c3-4099-9e9d-32f6ab1e92b7"
            on { idTokenSignedResponseAlgorithm } doReturn SigningAlgorithm.RS256
            on { idTokenEncryptedResponseAlgorithm } doReturn EncryptionAlgorithm.NONE
            on { idTokenEncryptedResponseEncoding } doReturn  EncryptionEncoding.NONE
        }

        val signAndEncryptClient = mock<JwksAwareClient> {
            on { id } doReturn "3721e748-d2db-4dd5-ae80-9a52642c5591"
            on { idTokenSignedResponseAlgorithm } doReturn SigningAlgorithm.RS256
            on { idTokenEncryptedResponseAlgorithm } doReturn EncryptionAlgorithm.RSA1_5
            on { idTokenEncryptedResponseEncoding } doReturn  EncryptionEncoding.AES_128_GCM
            on { jwksCache } doReturn JsonWebKeySet(
                RsaJwkGenerator.generateJwk(2048).apply {
                    keyId = "test-key"
                    use = Use.ENCRYPTION
                    algorithm = EncryptionAlgorithm.RSA1_5.value
                }
            ).toJson(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE)
        }

        val encryptOnlyClient = mock<JwksAwareClient> {
            on { id } doReturn "1d1fac28-9346-4630-99ec-56365474984f"
            on { idTokenSignedResponseAlgorithm } doReturn SigningAlgorithm.NONE
            on { idTokenEncryptedResponseAlgorithm } doReturn EncryptionAlgorithm.RSA1_5
            on { idTokenEncryptedResponseEncoding } doReturn  EncryptionEncoding.AES_128_GCM
            on { jwksCache } doReturn JsonWebKeySet(
                RsaJwkGenerator.generateJwk(2048).apply {
                    keyId = "test-key"
                    use = Use.ENCRYPTION
                    algorithm = EncryptionAlgorithm.RSA1_5.value
                }
            ).toJson()
        }

        val serverJwks = JsonWebKeySet(
            RsaJwkGenerator.generateJwk(2048).apply {
                keyId = "server-test-key"
                use = Use.SIGNATURE
                algorithm = SigningAlgorithm.RS256.value
            },
            RsaJwkGenerator.generateJwk(2048).apply {
                keyId = "server-test-key-2"
                use = Use.ENCRYPTION
                algorithm = EncryptionAlgorithm.RSA1_5.value
            }
        )

        val strategy = JwxIdTokenStrategy(
            lifespan = Duration.ofDays(1),
            signingAlgorithm = SigningAlgorithm.RS256,
            issuerUrl = "https://test.org",
            jwks = serverJwks
        )

        val helper = IdTokenHelper(strategy = strategy)

        val sampleSession = {
            ConnectSession(
                subject = "test user",
                obfuscatedSubject = "test user obfuscated",
                grantedScopes = mutableSetOf("foo", "bar"),
                clientId =  "",
                authTime = LocalDateTime.now().minusMinutes(5),
                nonce = "12345678",
                idClaims = mutableMapOf("custom" to "value")
            )
        }
    }
}