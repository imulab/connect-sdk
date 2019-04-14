package io.imulab.connect

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
