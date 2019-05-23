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

class AuthorizeCodeTest : FeatureSpec({

    feature("generate authorize code") {

        scenario("authorize request generates code") {
            val response: Response = mutableMapOf()
            val request = ConnectAuthorizeRequest(
                client = client,
                session = sampleSession
            )

            helper.issueCode(request, response).join()

            response.getCode().shouldNotBeEmpty()
        }
    }

    feature("validate authorize code") {

        scenario("valid authorize code") {
            val response: Response = mutableMapOf()
            val code = helper.issueCode(ConnectAuthorizeRequest(
                client = client,
                session = sampleSession
            ), response).join().let { response.getCode() }

            strategy.validateCode(code, ConnectSession())
        }

        scenario("invalid authorize code") {
            val response: Response = mutableMapOf()
            val code = helper.issueCode(ConnectAuthorizeRequest(
                client = client,
                session = sampleSession
            ), response).join().let { response.getCode() }

            shouldThrowAny {
                strategy.validateCode(code + "invalid", ConnectSession())
            }
        }
    }

    feature("compute identifier") {

        scenario("compute identifier of generated code") {
            val response: Response = mutableMapOf()
            val code = helper.issueCode(ConnectAuthorizeRequest(
                client = client,
                session = sampleSession
            ), response).join().let { response.getCode() }

            strategy.computeIdentifier(code).shouldNotBeEmpty()
        }
    }

}) {
    companion object {
        val client = mock<Client> {
            on { id } doReturn "8f9ba8b0-6361-4115-9535-cb11f2e8d59b"
        }

        private val repo = mock<AuthorizeCodeRepository> {
            onBlocking { getSession(anyOrNull()) } doAnswer { ic ->
                if (ic.arguments[0].toString().endsWith("invalid"))
                    throw Errors.invalidGrant("authorize code not found")
                else
                    sampleSession
            }
        }

        val strategy = HmacAuthorizeCodeStrategy(
            signingAlgorithm = SigningAlgorithm.HS256,
            key = AesKey("df36fc3665814870a076d038c8ff4a0f".toByteArray(StandardCharsets.UTF_8)),
            entropy = 32
        )

        val helper = AuthorizeCodeHelper(
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