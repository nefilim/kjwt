package io.github.nefilim.kjwt

import arrow.core.Either
import arrow.core.Option
import arrow.core.andThen
import arrow.core.computations.either
import arrow.core.computations.option
import arrow.core.invalidNel
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.ECGenParameterSpec

suspend fun <T: JWSECDSAAlgorithm> JWT<T>.sign(privateKey: ECPrivateKey): Either<KJWTSignError, SignedJWT<T>> {
    return this.header.algorithm.sign(this, JWSECDSAAlgorithm.signDigestWithPrivateKey(this.header.algorithm, privateKey))
}

suspend fun <T: JWSRSAAlgorithm> JWT<T>.sign(privateKey: RSAPrivateKey): Either<KJWTSignError, SignedJWT<T>> {
    return this.header.algorithm.sign(this, JWSRSAAlgorithm.signDigestWithPrivateKey(this.header.algorithm, privateKey))
}

fun <T: JWSHMACAlgorithm> JWT<T>.sign(secret: String): Either<KJWTSignError, SignedJWT<T>> {
    return this.header.algorithm.sign(this, secret)
}

// have to use fun interfaces to disambiguate the JVM signatures, a type parameter (eg a function) would be erased at runtime
fun interface PublicKeyProvider<R: PublicKey> {
    operator fun invoke(keyID: JWTKeyID): Option<R>
}
fun interface RSAPublicKeyProvider: PublicKeyProvider<RSAPublicKey> {
    override operator fun invoke(keyID: JWTKeyID): Option<RSAPublicKey>
}
fun interface ECPublicKeyProvider: PublicKeyProvider<ECPublicKey> {
    override operator fun invoke(keyID: JWTKeyID): Option<ECPublicKey>
}

// ------- [ Generic Asymmetric ]-----
fun <T: JWSAsymmetricAlgorithm<PubK, PrivK>, PubK: PublicKey, PrivK: PrivateKey>verifySignature(decodedJWT: DecodedJWT<T>, key: PubK): Either<KJWTVerificationError, JWT<T>> {
    return decodedJWT.jwt.header.algorithm.verifySignature(decodedJWT, key)
}
fun <T: JWSAsymmetricAlgorithm<PubK, PrivK>, PubK: PublicKey, PrivK: PrivateKey>verifySignature(jwt: String, key: PubK, algorithm: T): Either<KJWTVerificationError, JWT<T>> {
    return either.eager {
        val dJWTT = JWT.decodeT<T>(jwt, algorithm).bind()
        dJWTT.jwt.header.algorithm.verifySignature(dJWTT, key).bind()
    }
}
fun <T: JWSAsymmetricAlgorithm<PubK, PrivK>, PubK: PublicKey, PrivK: PrivateKey>verify(decodedJWT: DecodedJWT<T>, key: PubK, validator: ClaimsValidator): ClaimsValidatorResult {
    return verifySignature(decodedJWT, key).map {
        validator(it)
    }.fold({
        it.invalidNel()
    }, {
        it
    })
}
fun <T: JWSAsymmetricAlgorithm<PubK, PrivK>, PubK: PublicKey, PrivK: PrivateKey>verify(jwt: String, key: PubK, algorithm: T, validator: ClaimsValidator): ClaimsValidatorResult {
    return verifySignature<T, PubK, PrivK>(jwt, key, algorithm).map {
        validator(it)
    }.fold({
        it.invalidNel()
    }, {
        it
    })
}
fun <T: JWSAsymmetricAlgorithm<PubK, PrivK>, PubK: PublicKey, PrivK: PrivateKey>verify(decodedJWT: DecodedJWT<T>, keyProvider: PublicKeyProvider<PubK>, validator: ClaimsValidator): ClaimsValidatorResult {
    val publicKey = option.eager<PubK> {
        val keyID = decodedJWT.keyID().bind()
        keyProvider(keyID).bind()
    }.toEither { KJWTVerificationError.MissingKeyID }.toValidatedNel()
    return publicKey.andThen { verify(decodedJWT, it, validator) }
}
fun <T: JWSAsymmetricAlgorithm<PubK, PrivK>, PubK: PublicKey, PrivK: PrivateKey>verify(jwt: String, keyProvider: PublicKeyProvider<PubK>, algorithm: T, validator: ClaimsValidator): ClaimsValidatorResult {
    return JWT.decodeT<T>(jwt, algorithm).toValidatedNel().andThen { decodedJWT ->
        option.eager<Pair<DecodedJWT<T>, PubK>> {
            val keyID = decodedJWT.keyID().bind()
            val key = keyProvider(keyID).bind()
            decodedJWT to key
        }.toEither { KJWTVerificationError.MissingKeyID }.toValidatedNel()
    }.andThen { verify(it.first, it.second, validator) }
}

// --------[ convenience functions for fewer type parameters and constraining type combinations to valid ones ]---
fun <T: JWSRSAAlgorithm>verifySignature(decodedJWT: DecodedJWT<T>, key: RSAPublicKey): Either<KJWTVerificationError, JWT<T>> {
    return verifySignature<T, RSAPublicKey, RSAPrivateKey>(decodedJWT, key)
}
inline fun <reified T: JWSRSAAlgorithm>verifySignature(jwt: String, key: RSAPublicKey): Either<KJWTVerificationError, JWT<T>> {
    return verifySignature<T, RSAPublicKey, RSAPrivateKey>(jwt, key, algorithm())
}
fun <T: JWSECDSAAlgorithm>verifySignature(decodedJWT: DecodedJWT<T>, key: ECPublicKey): Either<KJWTVerificationError, JWT<T>> {
    return verifySignature<T, ECPublicKey, ECPrivateKey>(decodedJWT, key)
}
inline fun <reified T: JWSECDSAAlgorithm>verifySignature(jwt: String, key: ECPublicKey): Either<KJWTVerificationError, JWT<T>> {
    return verifySignature<T, ECPublicKey, ECPrivateKey>(jwt, key, algorithm())
}
@JvmName("verifyRSA") // avoid JVM type signature clash
fun <T: JWSRSAAlgorithm>verify(decodedJWT: DecodedJWT<T>, keyProvider: PublicKeyProvider<RSAPublicKey>, validator: ClaimsValidator): ClaimsValidatorResult {
    return verify<T, RSAPublicKey, RSAPrivateKey>(decodedJWT, keyProvider, validator)
}
@JvmName("verifyRSA") // avoid JVM type signature clash
inline fun <reified T: JWSRSAAlgorithm>verify(jwt: String, keyProvider: PublicKeyProvider<RSAPublicKey>, noinline validator: ClaimsValidator, algorithm: T = algorithm()): ClaimsValidatorResult {
    return verify<T, RSAPublicKey, RSAPrivateKey>(jwt, keyProvider, algorithm<T>(), validator)
}
@JvmName("verifyRSA") // avoid JVM type signature clash
inline fun <reified T: JWSRSAAlgorithm>verify(jwt: String, key: RSAPublicKey, noinline validator: ClaimsValidator, algorithm: T = algorithm()): ClaimsValidatorResult {
    return verify<T, RSAPublicKey, RSAPrivateKey>(jwt, key, algorithm(), validator)
}
@JvmName("verifyEC") // avoid JVM type signature clash
fun <T: JWSECDSAAlgorithm>verify(decodedJWT: DecodedJWT<T>, keyProvider: PublicKeyProvider<ECPublicKey>, validator: ClaimsValidator): ClaimsValidatorResult {
    return verify<T, ECPublicKey, ECPrivateKey>(decodedJWT, keyProvider, validator)
}
@JvmName("verifyEC") // avoid JVM type signature clash
inline fun <reified T: JWSECDSAAlgorithm>verify(jwt: String, keyProvider: PublicKeyProvider<ECPublicKey>, noinline validator: ClaimsValidator, algorithm: T = algorithm()): ClaimsValidatorResult {
    return verify<T, ECPublicKey, ECPrivateKey>(jwt, keyProvider, algorithm(), validator)
}
@JvmName("verifyEC") // avoid JVM type signature clash
inline fun <reified T: JWSECDSAAlgorithm>verify(jwt: String, key: ECPublicKey, noinline validator: ClaimsValidator, algorithm: T = algorithm()): ClaimsValidatorResult {
    return verify<T, ECPublicKey, ECPrivateKey>(jwt, key, algorithm(), validator)
}

// ------- [ HMAC ]-----
fun <T: JWSHMACAlgorithm>verifySignature(jwt: String, secret: String): Either<KJWTVerificationError, JWT<T>> {
    return either.eager {
        val dJWT = JWT.decode(jwt).bind()
        @Suppress("UNCHECKED_CAST")
        val dJWTT = Either.conditionally(dJWT.jwt.header.algorithm is JWSHMACAlgorithm, { KJWTVerificationError.AlgorithmMismatch }, { dJWT as DecodedJWT<T> }).bind()
        dJWTT.jwt.header.algorithm.verifySignature(dJWTT, secret).bind()
    }
}
fun <T: JWSHMACAlgorithm>verifySignature(decodedJWT: DecodedJWT<T>, secret: String): Either<KJWTVerificationError, JWT<T>> {
    return decodedJWT.jwt.header.algorithm.verifySignature(decodedJWT, secret)
}

fun <T: JWSHMACAlgorithm>verify(decodedJWT: DecodedJWT<T>, secret: String, validator: ClaimsValidator): ClaimsValidatorResult {
    return verifySignature<T>(decodedJWT, secret).map {
        validator(it)
    }.fold({
        it.invalidNel()
    }, {
        it
    })
}
inline fun <reified T: JWSHMACAlgorithm>verify(jwt: String, secret: String, noinline validator: ClaimsValidator): ClaimsValidatorResult {
    val decodedJWT = JWT.decodeT<T>(jwt, algorithm()).toValidatedNel()
    return decodedJWT.andThen { verify(it, secret, validator) }
}
fun interface HMACSecretProvider {
    operator fun invoke(keyID: JWTKeyID): Option<String>
}
fun <T: JWSHMACAlgorithm>verify(decodedJWT: DecodedJWT<T>, secretProvider: HMACSecretProvider, validator: ClaimsValidator): ClaimsValidatorResult {
    val secret = option.eager<String> {
        val keyID = decodedJWT.keyID().bind()
        secretProvider(keyID).bind()
    }.toEither { KJWTVerificationError.MissingKeyID }.toValidatedNel()
    return secret.andThen { verify(decodedJWT, it, validator) }
}

// ----- [ key generators ]----
fun generateKeyPair(algorithm: JWSECDSAAlgorithm): Pair<ECPublicKey, ECPrivateKey> {
    val ecSpec = ECGenParameterSpec(algorithm.curve)
    val g = KeyPairGenerator.getInstance("EC")
    g.initialize(ecSpec, SecureRandom())
    val keypair: KeyPair = g.generateKeyPair()
    return keypair.public as ECPublicKey to keypair.private as ECPrivateKey
}

fun generateKeyPair(algorithm: JWSRSAAlgorithm): Pair<RSAPublicKey, RSAPrivateKey> {
    val generator = KeyPairGenerator.getInstance("RSA")
    generator.initialize(algorithm.keyGenSpec)
    val kp = generator.genKeyPair()
    return kp.public as RSAPublicKey to kp.private as RSAPrivateKey
}