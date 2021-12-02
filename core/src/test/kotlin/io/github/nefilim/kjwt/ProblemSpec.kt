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
                    },
                    JWSRSA256Algorithm,
                )
                val jwtOpsEC = ECJWTOperations(
                    ECPublicKeyProvider {
                        generateKeyPair(JWSES384Algorithm).first.some()
                    },
                    JWSES384Algorithm,
                )

                processKnownToken("eyJhbGciOiJFUzI1NiIsInR5...", jwtOpsEC)
                processToken("eyJhbGciOiJFUzI1NiIsInR5...", jwtOpsRSA)
            }
        }
    }
}

fun <T: JWSAsymmetricAlgorithm<PubK, PrivK>, PubK: PublicKey, PrivK: PrivateKey>processToken(jwt: String, jwtOps: JWTOperations<T, PubK, PrivK>): ClaimsValidatorResult {
    val validator = validateClaims(notBefore, expired)
    return verify<T, PubK, PrivK>(jwt, jwtOps.keyProvider, jwtOps.algorithm, validator)
}

inline fun <reified T: JWSECDSAAlgorithm>processKnownToken(jwt: String, jwtOps: ECJWTOperations<T>): ClaimsValidatorResult {
    val validator = validateClaims(notBefore, expired)
    return verify<T>(jwt, jwtOps.keyProvider, validator)
}

interface JWTOperations<T: JWSAsymmetricAlgorithm<PubK, PrivK>, PubK: PublicKey, PrivK: PrivateKey> {
    val keyProvider: PublicKeyProvider<PubK>
    val algorithm: T
}

data class RSAJWTOperations<T: JWSRSAAlgorithm>(
    override val keyProvider: PublicKeyProvider<RSAPublicKey>,
    override val algorithm: T,
): JWTOperations<JWSRSAAlgorithm, RSAPublicKey, RSAPrivateKey>

data class ECJWTOperations<T: JWSECDSAAlgorithm>(
    override val keyProvider: PublicKeyProvider<ECPublicKey>,
    override val algorithm: T,
): JWTOperations<JWSECDSAAlgorithm, ECPublicKey, ECPrivateKey>