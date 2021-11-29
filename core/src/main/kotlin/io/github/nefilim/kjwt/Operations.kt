package io.github.nefilim.kjwt

import arrow.core.Either
import arrow.core.computations.either
import arrow.core.invalidNel
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey

suspend fun <T: JWSECDSAAlgorithm> JWT<T>.sign(privateKey: ECPrivateKey): Either<JWTSignError, SignedJWT<T>> {
    return this.header.algorithm.sign(this, JWSECDSAAlgorithm.signDigestWithPrivateKey(this.header.algorithm, privateKey))
}

suspend fun <T: JWSRSAAlgorithm> JWT<T>.sign(privateKey: RSAPrivateKey): Either<JWTSignError, SignedJWT<T>> {
    return this.header.algorithm.sign(this, JWSRSAAlgorithm.signDigestWithPrivateKey(this.header.algorithm, privateKey))
}

fun <T: JWSHMACAlgorithm> JWT<T>.sign(secret: String): Either<JWTSignError, SignedJWT<T>> {
    return this.header.algorithm.sign(this, secret)
}

fun <T: JWSRSAAlgorithm>verifySignature(jwt: String, key: RSAPublicKey): Either<JWTVerificationError, JWT<T>> {
    return either.eager {
        val dJWT = JWT.decode(jwt).bind()
        val dJWTT = Either.conditionally(dJWT.jwt.header.algorithm is JWSRSAAlgorithm, { JWTVerificationError.AlgorithmMismatch }, { dJWT as DecodedJWT<T> }).bind()
        dJWTT.jwt.header.algorithm.verifySignature(dJWTT, key, JWSRSAAlgorithm.signature(dJWTT)).bind()
    }
}

fun <T: JWSECDSAAlgorithm>verifySignature(jwt: String, key: ECPublicKey): Either<JWTVerificationError, JWT<T>> {
    return either.eager {
        val dJWT = JWT.decode(jwt).bind()
        val dJWTT = Either.conditionally(dJWT.jwt.header.algorithm is JWSECDSAAlgorithm, { JWTVerificationError.AlgorithmMismatch }, { dJWT as DecodedJWT<T> }).bind()
        dJWTT.jwt.header.algorithm.verifySignature(dJWTT, key, JWSECDSAAlgorithm.signature(dJWTT)).bind()
    }
}

fun <T: JWSHMACAlgorithm>verifySignature(jwt: String, secret: String): Either<JWTVerificationError, JWT<T>> {
    return either.eager {
        val dJWT = JWT.decode(jwt).bind()
        val dJWTT = Either.conditionally(dJWT.jwt.header.algorithm is JWSHMACAlgorithm, { JWTVerificationError.AlgorithmMismatch }, { dJWT as DecodedJWT<T> }).bind()
        dJWTT.jwt.header.algorithm.verifySignature(dJWTT, secret).bind()
    }
}

fun <T: JWSRSAAlgorithm>verify(jwt: String, key: RSAPublicKey, validator: ClaimsValidator): ClaimsValidatorResult {
    return verifySignature<T>(jwt, key).map {
        validator(it)
    }.fold({
        it.invalidNel()
    }, {
        it
    })
}

fun <T: JWSECDSAAlgorithm>verify(jwt: String, key: ECPublicKey, validator: ClaimsValidator): ClaimsValidatorResult {
    return verifySignature<T>(jwt, key).map {
        validator(it)
    }.fold({
        it.invalidNel()
    }, {
        it
    })
}

fun <T: JWSHMACAlgorithm>verify(jwt: String, secret: String, validator: ClaimsValidator): ClaimsValidatorResult {
    return verifySignature<T>(jwt, secret).map {
        validator(it)
    }.fold({
        it.invalidNel()
    }, {
        it
    })
}