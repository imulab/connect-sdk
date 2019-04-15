package io.imulab.connect

import com.nhaarman.mockitokotlin2.anyOrNull
import com.nhaarman.mockitokotlin2.doReturn
import com.nhaarman.mockitokotlin2.mock
import io.imulab.connect.client.Client
import io.imulab.connect.client.ClientSecretAware
import io.imulab.connect.client.SigningAlgorithm
import io.kotlintest.matchers.numerics.shouldBeGreaterThan
import io.kotlintest.matchers.string.shouldNotBeEmpty
import io.kotlintest.shouldBe
import io.kotlintest.shouldThrowAny
import io.kotlintest.specs.FeatureSpec
import org.jose4j.jwk.JsonWebKeySet
import org.jose4j.jwk.RsaJwkGenerator
import org.jose4j.jwk.Use
import java.time.Duration

class AccessTokenTest : FeatureSpec({

    feature("Access token can be generated") {
        scenario("new request generates access token using asymmetric algorithm") {
            val response: Response = mutableMapOf()
            val request = sampleRequest()
            asymmetricHelper.issueToken(request, response).join()

            response.getAccessToken().shouldNotBeEmpty()
            response.getExpiresIn() shouldBeGreaterThan 0
            response.getTokenType() shouldBe "Bearer"
        }

        scenario("new request generates access token using symmetric algorithm") {
            val response: Response = mutableMapOf()
            val request = sampleRequest()
            symmetricHelper.issueToken(request, response).join()

            response.getAccessToken().shouldNotBeEmpty()
            response.getExpiresIn() shouldBeGreaterThan 0
            response.getTokenType() shouldBe "Bearer"
        }
    }


    feature("Access token can be validated") {

        scenario("generated token using asymmetric algorithm can be validated") {
            val response: Response = mutableMapOf()
            val oldToken = asymmetricHelper.issueToken(sampleRequest(), response).join().let {
                response.getAccessToken()
            }

            asymmetricStrategy.validateToken(oldToken, ConnectTokenRequest(
                _client = client
            ))
        }

        scenario("generated token using symmetric algorithm can be validated") {
            val response: Response = mutableMapOf()
            val oldToken = symmetricHelper.issueToken(sampleRequest(), response).join().let {
                response.getAccessToken()
            }

            symmetricStrategy.validateToken(oldToken, ConnectTokenRequest(
                _client = client
            ))
        }

        scenario("invalid access token should fail validation") {
            val response: Response = mutableMapOf()
            val oldToken = asymmetricHelper.issueToken(sampleRequest(), response).join().let {
                response.getAccessToken()
            }

            /*
             * Failure scenario:
             * Token is generated with asymmetric strategy, but use symmetric strategy
             * to validate it.
             */

            shouldThrowAny {
                symmetricStrategy.validateToken(oldToken, ConnectTokenRequest(
                    _client = client
                ))
            }
        }
    }

    feature("JWT access token strategy computes token identifier") {
        scenario("generated token can calculate its identifier") {
            val response: Response = mutableMapOf()
            val oldToken = asymmetricHelper.issueToken(sampleRequest(), response).join().let {
                response.getAccessToken()
            }

            asymmetricStrategy.computeIdentifier(oldToken).shouldNotBeEmpty()
        }
    }
}) {
    companion object {
        interface SecretAwareClient : Client, ClientSecretAware

        val client = mock<SecretAwareClient> {
            on { id } doReturn "4a1f3d25-7f55-498d-93e3-430fa0429a10"
            on { secret } doReturn "ff2b986a7a324b548d31f4673430706d"
            on { plainTextSecret() } doReturn "ff2b986a7a324b548d31f4673430706d"
        }

        private val repo = mock<AccessTokenRepository> {
            onBlocking { getSession(anyOrNull()) } doReturn ConnectSession()
            onBlocking { save(anyOrNull(), anyOrNull()) } doReturn Unit
            onBlocking { delete(anyOrNull()) } doReturn Unit
            onBlocking { deleteByRequestId(anyOrNull()) } doReturn Unit
        }

        val asymmetricStrategy = JwtAccessTokenStrategy(
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
        )

        val symmetricStrategy = JwtAccessTokenStrategy(
            signingAlgorithm = SigningAlgorithm.HS256,
            jwks = JsonWebKeySet(),
            issuerUrl = "https://test.org",
            lifespan = Duration.ofMinutes(30)
        )

        val asymmetricHelper = AccessTokenHelper(
            lifespan = Duration.ofMinutes(30),
            repository = repo,
            strategy = asymmetricStrategy
        )

        val symmetricHelper = AccessTokenHelper(
            lifespan = Duration.ofMinutes(30),
            repository = repo,
            strategy = symmetricStrategy
        )

        fun sampleRequest(): ConnectTokenRequest = ConnectTokenRequest(
            _client = client,
            session = ConnectSession(
                subject = "test user",
                obfuscatedSubject = "test user",
                grantedScopes = mutableSetOf("foo", "bar"),
                clientId = client.id,
                accessClaims = mutableMapOf(
                    "custom" to "value"
                )
            )
        )
    }
}
