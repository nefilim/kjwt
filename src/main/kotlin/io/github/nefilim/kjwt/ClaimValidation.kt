package io.github.nefilim.kjwt

import arrow.core.None
import arrow.core.Option
import arrow.core.Some
import arrow.core.Validated
import arrow.core.ValidatedNel
import arrow.core.invalidNel
import arrow.core.validNel
import arrow.core.zip
import arrow.typeclasses.Semigroup
import java.time.LocalDateTime


sealed interface JWTValidationError: JWTVerificationError {
    object TokenExpired: JWTValidationError
    object TokenNotValidYet: JWTValidationError
    object InvalidIssuer: JWTValidationError
    object InvalidSubject: JWTValidationError
    object InvalidAudience: JWTValidationError
    data class RequiredClaimIsMissing(val name: String): JWTValidationError
    data class RequiredClaimIsInvalid(val name: String): JWTValidationError
}

typealias ClaimsValidatorResult = ValidatedNel<out JWTVerificationError, JWTClaims>
typealias ClaimsValidator = (JWTClaims) -> ClaimsValidatorResult

object ClaimsVerification {
    fun issuer(issuer: String): ClaimsValidator = requiredOptionClaim("issuer", { issuer() }, { it == issuer }, JWTValidationError.InvalidIssuer)

    fun subject(subject: String): ClaimsValidator = requiredOptionClaim("subject", { subject() }, { it == subject }, JWTValidationError.InvalidSubject)

    fun audience(audience: String): ClaimsValidator = requiredOptionClaim("audience", { audience() }, { it == audience }, JWTValidationError.InvalidAudience)

    val expired: ClaimsValidator = requiredOptionClaim("expired", { expiresAt() }, { it.isAfter(LocalDateTime.now()) }, JWTValidationError.TokenExpired)

    val notBefore: ClaimsValidator = requiredOptionClaim("notBefore", { notBefore() }, { it.isBefore(LocalDateTime.now()) }, JWTValidationError.TokenNotValidYet)

    fun <T>requiredOptionClaim(
        name: String,
        claim: JWTClaims.() -> Option<T>,
        predicate: (T) -> Boolean,
    ): ClaimsValidator = requiredOptionClaim(name, claim, predicate, JWTValidationError.RequiredClaimIsInvalid(name))

    fun <T>requiredOptionClaim(
        name: String,
        claim: JWTClaims.() -> Option<T>,
        predicate: (T) -> Boolean,
        error: JWTValidationError,
    ): ClaimsValidator = { claims ->
        when (claims.claim()) {
            is Some -> predicate((claims.claim() as Some<T>).value).toValidatedNel(error, claims)
            is None -> JWTValidationError.RequiredClaimIsMissing(name).invalidNel()
        }
    }

    fun <T>optionalOptionClaim(
        name: String,
        claim: JWTClaims.() -> Option<T>,
        predicate: (T) -> Boolean,
    ): ClaimsValidator = optionalOptionClaim(name, claim, predicate, JWTValidationError.RequiredClaimIsInvalid(name))

    fun <T>optionalOptionClaim(
        name: String,
        claim: JWTClaims.() -> Option<T>,
        predicate: (T) -> Boolean,
        error: JWTValidationError = JWTValidationError.RequiredClaimIsInvalid(name),
    ): ClaimsValidator = { claims ->
        when (claims.claim()) {
            is Some -> predicate((claims.claim() as Some<T>).value).toValidatedNel(error, claims)
            is None -> claims.validNel()
        }
    }

    private fun Boolean.toValidatedNel(invalid: JWTValidationError, claims: JWTClaims): ClaimsValidatorResult {
        return if (this)
            claims.validNel()
        else
            invalid.invalidNel()
    }

    fun validateClaims(vararg validations: ClaimsValidator): ClaimsValidator = { claims ->
        validations.fold(Validated.validNel(claims)) { c, t ->
            c.zip(Semigroup.nonEmptyList(), t(claims)) { c1, _ -> c1 }
        }
    }
}