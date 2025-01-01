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
import java.time.Clock
import java.time.temporal.ChronoUnit

sealed interface KJWTValidationError: KJWTVerificationError {
    object TokenExpired: KJWTValidationError
    object TokenNotValidYet: KJWTValidationError
    object InvalidIssuer: KJWTValidationError
    object InvalidSubject: KJWTValidationError
    object InvalidAudience: KJWTValidationError
    data class RequiredClaimIsMissing(val name: String): KJWTValidationError
    data class RequiredClaimIsInvalid(val name: String): KJWTValidationError
}

typealias ClaimsValidatorResult = ValidatedNel<KJWTVerificationError, JWTClaims>
typealias ClaimsValidator = (JWTClaims) -> ClaimsValidatorResult

object ClaimsVerification {
    fun issuer(issuer: String): ClaimsValidator = requiredOptionClaim("issuer", { issuer() }, { it == issuer }, KJWTValidationError.InvalidIssuer)

    fun subject(subject: String): ClaimsValidator = requiredOptionClaim("subject", { subject() }, { it == subject }, KJWTValidationError.InvalidSubject)

    fun audience(audience: String): ClaimsValidator = requiredOptionClaim("audience", { audience() }, { it == audience }, KJWTValidationError.InvalidAudience)

    fun expired(clock: Clock = Clock.systemUTC()): ClaimsValidator = requiredOptionClaim(
        "expired",
        { expiresAt() },
        { it.isAfter(clock.instant().truncatedTo(ChronoUnit.SECONDS)) },
        KJWTValidationError.TokenExpired
    )

    fun notBefore(clock: Clock = Clock.systemUTC()): ClaimsValidator = requiredOptionClaim(
        "notBefore",
        { notBefore() },
        { it.isBefore(clock.instant().truncatedTo(ChronoUnit.SECONDS)) },
        KJWTValidationError.TokenNotValidYet
    )

    fun <T>requiredOptionClaim(
        name: String,
        claim: JWTClaims.() -> Option<T>,
        predicate: (T) -> Boolean,
    ): ClaimsValidator = requiredOptionClaim(name, claim, predicate, KJWTValidationError.RequiredClaimIsInvalid(name))

    fun <T>requiredOptionClaim(
        name: String,
        claim: JWTClaims.() -> Option<T>,
        predicate: (T) -> Boolean,
        error: KJWTValidationError,
    ): ClaimsValidator = { claims ->
        when (claims.claim()) {
            is Some -> predicate((claims.claim() as Some<T>).value).toValidatedNel(error, claims)
            is None -> KJWTValidationError.RequiredClaimIsMissing(name).invalidNel()
        }
    }

    fun <T>optionalOptionClaim(
        name: String,
        claim: JWTClaims.() -> Option<T>,
        predicate: (T) -> Boolean,
    ): ClaimsValidator = optionalOptionClaim(name, claim, predicate, KJWTValidationError.RequiredClaimIsInvalid(name))

    fun <T>optionalOptionClaim(
        name: String,
        claim: JWTClaims.() -> Option<T>,
        predicate: (T) -> Boolean,
        error: KJWTValidationError = KJWTValidationError.RequiredClaimIsInvalid(name),
    ): ClaimsValidator = { claims ->
        when (claims.claim()) {
            is Some -> predicate((claims.claim() as Some<T>).value).toValidatedNel(error, claims)
            is None -> claims.validNel()
        }
    }

    private fun Boolean.toValidatedNel(invalid: KJWTValidationError, claims: JWTClaims): ClaimsValidatorResult {
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