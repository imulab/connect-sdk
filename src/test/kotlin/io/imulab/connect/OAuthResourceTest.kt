package io.imulab.connect

import com.nhaarman.mockitokotlin2.anyOrNull
import com.nhaarman.mockitokotlin2.mock
import io.imulab.connect.spi.HttpRequest
import io.imulab.connect.spi.OAuthResource
import io.kotlintest.matchers.boolean.shouldBeTrue
import io.kotlintest.matchers.types.shouldBeInstanceOf
import io.kotlintest.shouldBe
import io.kotlintest.shouldNotThrowAny
import io.kotlintest.specs.FeatureSpec
import org.jose4j.jwt.JwtClaims

class OAuthResourceTest : FeatureSpec({

    feature("oauth resource protection") {
        val testResource = object : OAuthResource {
            override val accessTokenStrategy: AccessTokenStrategy
                get() = mockAccessTokenStrategy
            override val requiredScopes: Set<String>
                get() = setOf("foo", "bar")
        }

        scenario("token with sufficient grant can access the resource") {
            val httpRequest = mock<HttpRequest> {
                on { it.header("Authorization") }.thenReturn("Bearer sufficient")
            }

            shouldNotThrowAny {
                testResource.protected(httpRequest)
            }
        }

        scenario("token without sufficient grant is rejected") {
            val httpRequest = mock<HttpRequest> {
                on { it.header("Authorization") }.thenReturn("Bearer insufficient")
            }

            val result = kotlin.runCatching { testResource.protected(httpRequest) }

            result.isFailure.shouldBeTrue()
            result.exceptionOrNull()!!.shouldBeInstanceOf<ConnectException>()
            (result.exceptionOrNull()!! as ConnectException).error.shouldBe(Errors.Codes.accessDenied)
        }

        scenario("invalid token is rejected") {
            val httpRequest = mock<HttpRequest> {
                on { it.header("Authorization") }.thenReturn("Bearer bad")
            }

            val result = kotlin.runCatching { testResource.protected(httpRequest) }

            result.isFailure.shouldBeTrue()
            result.exceptionOrNull()!!.shouldBeInstanceOf<ConnectException>()
            (result.exceptionOrNull()!! as ConnectException).error.shouldBe(Errors.Codes.invalidGrant)
        }
    }
}) {

    companion object {
        val mockAccessTokenStrategy = mock<AccessTokenStrategy> {
            onBlocking {
                it.validateToken(anyOrNull(), anyOrNull())
            }.then { ic ->
                when (ic.arguments[0]!!.toString()) {
                    "sufficient" -> JwtClaims().also { c -> c.setScope(setOf("foo", "bar")) }
                    "insufficient" -> JwtClaims().also { c -> c.setScope(setOf("foo")) }
                    else -> throw Errors.invalidGrant("bad token")
                }
            }
        }
    }
}