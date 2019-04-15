package io.imulab.connect

import io.imulab.connect.auth.CLIENT_ID
import io.imulab.connect.client.ResponseType
import io.imulab.connect.parse.*
import org.jose4j.jwt.JwtClaims
import org.jose4j.jwt.NumericDate
import java.time.LocalDateTime
import java.time.ZoneOffset

private const val scope = "scope"
private const val authTime = "auth_time"
private const val nonce = "nonce"
private const val acrValues = "acr_values"
private const val space = " "

fun LocalDateTime.toNumericDate(): NumericDate = NumericDate.fromSeconds(toEpochSecond(ZoneOffset.UTC))

fun JwtClaims.setScope(scopes: Collection<String>) =
    this.setStringClaim(scope, scopes.joinToString(separator = space))

fun JwtClaims.setAuthTime(time: LocalDateTime?) {
    if (time != null)
        this.setNumericDateClaim(authTime, time.toNumericDate())
}

fun JwtClaims.setNonce(value: String) {
    if (nonce.isNotEmpty())
        this.setStringClaim(nonce, value)
}

fun JwtClaims.setAcrValues(values: Collection<String>) {
    if (values.isNotEmpty())
        this.setClaim(acrValues, values)
}

fun JwtClaims.getResponseTypes(): List<ResponseType> =
    safeString(RESPONSE_TYPE).spaceSplit().map { ResponseType.parse(it) }

fun JwtClaims.getClientId(): String = safeString(CLIENT_ID)

fun JwtClaims.getRedirectUri(): String = safeString(REDIRECT_URI)

fun JwtClaims.getScopes(): Set<String> = safeString(SCOPE).spaceSplit().toSet()

fun JwtClaims.getState(): String = safeString(STATE)

fun JwtClaims.getResponseMode(): ResponseMode? =
    safeString(RESPONSE_MODE).nonEmptyOrNull()?.let { ResponseMode.parse(it) }

fun JwtClaims.getDisplay(): Display? =
    safeString(DISPLAY).nonEmptyOrNull()?.let { Display.parse(it) }

fun JwtClaims.getPrompts(): Set<Prompt> =
    safeString(PROMPT).spaceSplit().map { Prompt.parse(it) }.toSet()

fun JwtClaims.getMaxAge(): Long = safeString(MAX_AGE).toLongOrNull() ?: 0L

fun JwtClaims.getNonce(): String = safeString(NONCE)

fun JwtClaims.getUiLocales(): List<String> = safeString(UI_LOCALES).spaceSplit()

fun JwtClaims.getIdTokenHint(): String = safeString(ID_TOKEN_HINT)

fun JwtClaims.getLoginHint(): String = safeString(LOGIN_HINT)

fun JwtClaims.getAcrValues(): List<String> = safeString(ACR_VALUES).spaceSplit()

fun JwtClaims.getClaimsLocales(): List<String> = safeString(CLAIMS_LOCALES).spaceSplit()

/*
 * JwtClaims extension design does not cover claims as it would require an SPI reference fo JsonProvider to be
 * passed in. Such API design is not considered ideal, hence getting 'claims' from the JwtClaims object will
 * be designed as private methods where a JsonProvider is available.
 */

/**
 * Utility method to safely get string from JwtClaims.
 */
fun JwtClaims.safeString(name: String): String =
    kotlin.runCatching { getStringClaimValue(name) }.getOrDefault("")