package io.imulab.connect

import com.nhaarman.mockitokotlin2.doReturn
import com.nhaarman.mockitokotlin2.mock
import io.imulab.connect.client.Client
import io.imulab.connect.client.GrantType
import io.imulab.connect.client.ResponseType
import io.kotlintest.matchers.collections.shouldContainExactly
import io.kotlintest.matchers.maps.shouldContainExactly
import io.kotlintest.shouldBe
import io.kotlintest.shouldNotBe
import io.kotlintest.specs.BehaviorSpec
import java.time.LocalDateTime

class RequestTest : BehaviorSpec({
    val mockClient = mock<Client> {
        on { id } doReturn "b6c9e044-9729-439b-a9f9-376ad129f314"
    }

    given("two session (first and second)") {
        val first = {
            ConnectSession(
                clientId = "foo"
            )
        }
        val second = {
            ConnectSession(
                subject = "test",
                obfuscatedSubject = "test",
                savedByRequestId = "last-request",
                grantedScopes = mutableSetOf("foo", "bar"),
                accessClaims = mutableMapOf("foo" to "bar"),
                idClaims = mutableMapOf("foo" to "bar"),
                authTime = LocalDateTime.now()
            )
        }

        `when`("replaced") {
            val f = first()
            val s = second()
            f.replacedWith(s)

            then("first should have second's value where it is not null or empty") {
                val f0 = first()
                val s0 = second()

                f.clientId shouldBe f0.clientId
                f.subject shouldBe s0.subject
                f.obfuscatedSubject shouldBe s0.obfuscatedSubject
                f.savedByRequestId shouldBe s0.savedByRequestId
                f.grantedScopes shouldContainExactly s0.grantedScopes
                f.accessClaims shouldContainExactly s0.accessClaims
                f.idClaims shouldContainExactly s0.idClaims
                f.authTime shouldNotBe null
            }
        }
    }

    given("two token request (first and second)") {
        val first = {
            ConnectTokenRequest(
                client = mockClient,
                redirectUri = "https://test.org/callback",
                grantTypes = mutableSetOf(GrantType.CODE),
                code = "a-code"
            )
        }
        val second = {
            ConnectTokenRequest(
                client = mockClient,
                code = "b-code",
                grantTypes = mutableSetOf(GrantType.CODE, GrantType.REFRESH),
                refreshToken = "b-token"
            )
        }

        `when`("first is hard merged with second") {
            val f = first()
            val s = second()
            f.mergeWith(s, hard = true)

            then("second's value replaces first if it is not null or empty") {
                f.client.id shouldBe s.client.id
                f.code shouldBe s.code
                f.grantTypes shouldContainExactly s.grantTypes
                f.refreshToken shouldBe s.refreshToken
            }

            then("second's value does not replace first if it is null or empty") {
                val expected = first()
                f.redirectUri shouldBe expected.redirectUri
            }
        }

        `when`("first is soft merged with second") {
            val f = first()
            val s = second()
            f.mergeWith(s, hard = false)

            then("second's value replaces first where first value is null or empty") {
                f.refreshToken shouldBe s.refreshToken
            }

            then("second's value does not replace first where first value is not null or empty") {
                val expected = first()
                f.client.id shouldBe expected.client.id
                f.grantTypes shouldContainExactly expected.grantTypes
                f.code shouldBe expected.code
                f.redirectUri shouldBe expected.redirectUri
            }
        }
    }

    given("two authorize request (first and second)") {
        val first = {
            ConnectAuthorizeRequest(
                client = mockClient,
                scopes = mutableSetOf("foo"),
                state = "12345678",
                nonce = "87654321",
                responseMode = ResponseMode.QUERY,
                display = Display.PAGE,
                session = ConnectSession()
            )
        }
        val second = {
            ConnectAuthorizeRequest(
                redirectUri = "https://test.org/callback",
                scopes = mutableSetOf("bar"),
                responseTypes = mutableSetOf(ResponseType.CODE),
                prompt = mutableSetOf(Prompt.NONE),
                maxAge = 3600L
            )
        }

        `when`("first is hard merged with second") {
            val f = first()
            val s = second()
            f.mergeWith(s, hard = true)

            then("second's value replaces first if it is not null or empty") {
                f.redirectUri shouldBe s.redirectUri
                f.scopes shouldContainExactly s.scopes
                f.responseTypes shouldContainExactly s.responseTypes
                f.prompt shouldContainExactly s.prompt
                f.maxAge shouldBe s.maxAge
            }

            then("second's value does not replace first if it is null or empty") {
                val expected = first()

                f.client.id shouldBe expected.client.id
                f.state shouldBe expected.state
                f.nonce shouldBe expected.nonce
                f.responseMode shouldBe expected.responseMode
                f.display shouldBe expected.display
            }
        }

        `when`("first is soft merged with second") {
            val f = first()
            val s = second()
            f.mergeWith(s, hard = false)

            then("second's value replaces first where first value is null or empty") {
                f.redirectUri shouldBe s.redirectUri
                f.responseTypes shouldContainExactly s.responseTypes
                f.prompt shouldContainExactly s.prompt
                f.maxAge shouldBe s.maxAge
            }

            then("second's value does not replace first where first value is not null or empty") {
                val expected = first()

                f.client.id shouldBe expected.client.id
                f.scopes shouldContainExactly expected.scopes
                f.state shouldBe expected.state
                f.nonce shouldBe expected.nonce
                f.responseMode shouldBe expected.responseMode
                f.display shouldBe expected.display
            }
        }
    }
})