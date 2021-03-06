package io.imulab.connect

import com.nhaarman.mockitokotlin2.anyOrNull
import com.nhaarman.mockitokotlin2.doAnswer
import com.nhaarman.mockitokotlin2.doReturn
import com.nhaarman.mockitokotlin2.mock
import io.imulab.connect.client.Client
import io.imulab.connect.client.SigningAlgorithm
import io.kotlintest.matchers.string.shouldNotBeEmpty
import io.kotlintest.shouldThrowAny
import io.kotlintest.specs.FeatureSpec
import org.jose4j.keys.AesKey
import java.nio.charset.StandardCharsets

class RefreshTokenTest: FeatureSpec({

    feature("generate refresh token") {

        scenario("token request generates refresh token") {
            val response: Response = mutableMapOf()
            val request = ConnectTokenRequest(
                client = AuthorizeCodeTest.client,
                session = AuthorizeCodeTest.sampleSession
            )

            helper.issueToken(request, response).join()

            response.getRefreshToken().shouldNotBeEmpty()
        }
    }

    feature("validate refresh token") {

        scenario("valid refresh token") {
            val response: Response = mutableMapOf()
            val refreshToken = helper.issueToken(ConnectTokenRequest(
                client = client,
                session = sampleSession
            ), response).join().let { response.getRefreshToken() }

            strategy.validateToken(refreshToken, ConnectSession())
        }

        scenario("invalid refresh token") {
            val response: Response = mutableMapOf()
            val refreshToken = helper.issueToken(ConnectTokenRequest(
                client = client,
                session = sampleSession
            ), response).join().let { response.getRefreshToken() }

            shouldThrowAny {
                strategy.validateToken(refreshToken + "invalid", ConnectSession())
            }
        }
    }

    feature("compute identifier") {

        scenario("compute identifier of generated refresh token") {
            val response: Response = mutableMapOf()
            val refreshToken = helper.issueToken(ConnectTokenRequest(
                client = client,
                session = sampleSession
            ), response).join().let { response.getRefreshToken() }

            strategy.computeIdentifier(refreshToken).shouldNotBeEmpty()
        }
    }

}) {

   companion object {
       val client = mock<Client> {
           on { id } doReturn "8f9ba8b0-6361-4115-9535-cb11f2e8d59b"
       }

       private val repo = mock<RefreshTokenRepository> {
           onBlocking { getSession(anyOrNull()) } doAnswer { ic ->
               if (ic.arguments[0].toString().endsWith("invalid"))
                   throw Errors.invalidGrant("refresh code not found")
               else
                   sampleSession
           }
       }

       val strategy = HmacRefreshTokenStrategy(
           signingAlgorithm = SigningAlgorithm.HS256,
           key = AesKey("df36fc3665814870a076d038c8ff4a0f".toByteArray(StandardCharsets.UTF_8)),
           entropy = 32
       )

       val helper = RefreshTokenHelper(
           strategy = strategy,
           repository = repo
       )

       val sampleSession = ConnectSession(
           subject = "test user",
           obfuscatedSubject = "test user obfuscated",
           clientId = client.id,
           grantedScopes = mutableSetOf("foo", "bar")
       )
   }
}