package io.github.nefilim.kjwt

import arrow.core.some
import io.github.nefilim.kjwt.ClaimsVerification.expired
import io.github.nefilim.kjwt.ClaimsVerification.notBefore
import io.github.nefilim.kjwt.ClaimsVerification.validateClaims
import io.kotest.core.spec.style.WordSpec
import java.security.PrivateKey
import java.security.PublicKey
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey

class ProblemSpec: WordSpec() {
    init {
        "kJWT" should {
            "be somewhat sane to use" {
                val jwtOpsRSA = RSAJWTOperations(
                    RSAPublicKeyProvider {
                        generateKeyPair(JWSRSA256Algorithm).first.some()
                    }
                )

                processToken("eyJhbGciOiJFUzI1NiIsInR5...", jwtOpsRSA)
            }
        }
    }
}

fun <T: JWSAsymmetricAlgorithm<PubK, PrivK>, PubK: PublicKey, PrivK: PrivateKey>processToken(jwt: String, jwtOps: JWTOperations<T, PubK, PrivK>): ClaimsValidatorResult {
    val validator = validateClaims(notBefore, expired)
    return verify<T, PubK, PrivK>(jwt, jwtOps.keyProvider, validator)
}

fun <T: JWSECDSAAlgorithm>processKnownToken(jwt: String, jwtOps: ECJWTOperations): ClaimsValidatorResult {
    val validator = validateClaims(notBefore, expired)
    return verify<T>(jwt, jwtOps.keyProvider, validator)
}

interface JWTOperations<T: JWSAsymmetricAlgorithm<PubK, PrivK>, PubK: PublicKey, PrivK: PrivateKey> {
    val keyProvider: PublicKeyProvider<PubK>
}

data class RSAJWTOperations(
    override val keyProvider: PublicKeyProvider<RSAPublicKey>
): JWTOperations<JWSRSAAlgorithm, RSAPublicKey, RSAPrivateKey>

data class ECJWTOperations(
    override val keyProvider: PublicKeyProvider<ECPublicKey>
): JWTOperations<JWSECDSAAlgorithm, ECPublicKey, ECPrivateKey>