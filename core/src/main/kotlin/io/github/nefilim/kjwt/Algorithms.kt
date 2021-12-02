package io.github.nefilim.kjwt

import arrow.core.Either
import arrow.core.computations.either
import arrow.core.flatMap
import arrow.core.left
import arrow.core.right
import kotlin.reflect.typeOf
import kotlinx.serialization.Serializable
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.SignatureException
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.RSAKeyGenParameterSpec
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

sealed interface KJWTError

sealed interface KJWTSignError: KJWTError {
    object InvalidKey: KJWTSignError
    object InvalidJWTData: KJWTSignError
    data class SigningError(val cause: Throwable): KJWTSignError
}

sealed interface KJWTVerificationError: KJWTError {
    object InvalidJWT: KJWTVerificationError
    object MissingKeyID: KJWTVerificationError
    object AlgorithmMismatch: KJWTVerificationError
    object KeyAlgorithmMismatch: KJWTVerificationError
    object BrokenSignature: KJWTVerificationError
    object InvalidSignature: KJWTVerificationError
    object MissingSignature: KJWTVerificationError
    object EmptyClaims: KJWTVerificationError
}

typealias SignEncodedJWT = suspend (String) -> Either<KJWTSignError, ByteArray>

sealed interface JWSAlgorithm {
    val headerID: String
    val algorithmName: String
    val jwtCreator: (JWTKeyID?, (JWT.Companion.JWTClaimSetBuilder.() -> Unit)) -> JWT<*>
}
sealed interface JWSSymmetricAlgorithm: JWSAlgorithm {
    fun <T: JWSSymmetricAlgorithm>sign(jwt: JWT<T>, secret: String): Either<KJWTSignError, SignedJWT<T>> {
        return either.eager<KJWTSignError, ByteArray> {
            val nonBlankSecret = Either.conditionally(secret.isNotBlank(), { KJWTSignError.InvalidKey }, { secret }).bind()
            val secretBytes = stringToBytes(nonBlankSecret).mapLeft { KJWTSignError.InvalidKey }.bind()
            val dataToSign = stringToBytes(jwt.encode()).mapLeft { KJWTSignError.InvalidJWTData }.bind()
            Either.catch {
                val mac = Mac.getInstance(jwt.header.algorithm.algorithmName)
                mac.init(SecretKeySpec(secretBytes, jwt.header.algorithm.algorithmName))
                mac.doFinal(dataToSign)
            }.mapLeft { KJWTSignError.SigningError(it) }.bind()
        }.map {
            SignedJWT(jwt, it, jwt.header.algorithm)
        }
    }
    fun <T: JWSSymmetricAlgorithm>verifySignature(dJWT: DecodedJWT<T>, secret: String): Either<KJWTVerificationError, JWT<T>> {
        return either.eager<KJWTVerificationError, JWT<T>> {
            val signature = Either.fromNullable(dJWT.signature()).mapLeft { KJWTVerificationError.MissingSignature }.bind()
            val signedJWT = sign(dJWT.jwt, secret).mapLeft { KJWTVerificationError.InvalidJWT }.bind()
            Either.conditionally(jwtEncodeBytes(signedJWT.signature) == signature, { KJWTVerificationError.InvalidSignature }, { dJWT.jwt} ).bind()
        }
    }
}

sealed interface JWSHMACAlgorithm: JWSSymmetricAlgorithm
@Serializable
object JWSHMAC256Algorithm: JWSHMACAlgorithm {
    override val headerID: String = "HS256"
    override val algorithmName: String = "HmacSHA256"
    override val jwtCreator: (JWTKeyID?, JWT.Companion.JWTClaimSetBuilder.() -> Unit) -> JWT<JWSHMAC256Algorithm> = JWT.Companion::hs256
}
@Serializable
object JWSHMAC384Algorithm: JWSHMACAlgorithm {
    override val headerID: String = "HS384"
    override val algorithmName: String = "HmacSHA384"
    override val jwtCreator: (JWTKeyID?, JWT.Companion.JWTClaimSetBuilder.() -> Unit) -> JWT<JWSHMAC384Algorithm> = JWT.Companion::hs384
}
@Serializable
object JWSHMAC512Algorithm: JWSHMACAlgorithm {
    override val headerID: String = "HS512"
    override val algorithmName: String = "HmacSHA512"
    override val jwtCreator: (JWTKeyID?, JWT.Companion.JWTClaimSetBuilder.() -> Unit) -> JWT<JWSHMAC512Algorithm> = JWT.Companion::hs512
}

// let go of recursive type to be able to be specific in the derived interfaces (signature) to improve usability elsewhere
//sealed interface JWSAsymmetricAlgorithm<T: JWSAsymmetricAlgorithm<T, PubK, PrivK>, PubK: PublicKey, PrivK: PrivateKey>: JWSAlgorithm {
sealed interface JWSAsymmetricAlgorithm<PubK: PublicKey, PrivK: PrivateKey>: JWSAlgorithm {
    fun <T: JWSAsymmetricAlgorithm<PubK, PrivK>>verifySignature(dJWT: DecodedJWT<T>, key: PubK): Either<KJWTVerificationError, JWT<T>> {
        val signer = Signature.getInstance(dJWT.jwt.header.algorithm.algorithmName)

        return either.eager<KJWTVerificationError, Boolean> {
            Either.catch { signer.initVerify(key) }.mapLeft { KJWTVerificationError.KeyAlgorithmMismatch }.bind()
            val dataToVerify = Either.catch { dJWT.signedData().toByteArray() }.mapLeft { KJWTVerificationError.InvalidJWT }.bind()
            val sig = signature(dJWT).bind()
            Either.catch { signer.update(dataToVerify) }.mapLeft { KJWTVerificationError.BrokenSignature }.bind()
            Either.catch { signer.verify(sig) }.mapLeft { KJWTVerificationError.BrokenSignature }.bind()
        }.flatMap {
            Either.conditionally(it, { KJWTVerificationError.InvalidSignature }, { dJWT.jwt })
        }
    }
    fun <T: JWSAsymmetricAlgorithm<PubK, PrivK>>signature(dJWT: DecodedJWT<T>): Either<KJWTVerificationError, ByteArray>
}

sealed interface JWSRSAAlgorithm: JWSAsymmetricAlgorithm<RSAPublicKey, RSAPrivateKey> {
    suspend fun <T: JWSRSAAlgorithm>sign(jwt: JWT<T>, signDigest: SignEncodedJWT): Either<KJWTSignError, SignedJWT<T>> {
        return either<KJWTSignError, ByteArray> {
            val encoded = Either.catch { jwt.encode() }.mapLeft { KJWTSignError.SigningError(it) }.bind()
            signDigest(encoded).bind()
        }.map { sig ->
            SignedJWT(jwt, sig, jwt.header.algorithm)
        }
    }

    override fun <T: JWSAsymmetricAlgorithm<RSAPublicKey, RSAPrivateKey>>signature(dJWT: DecodedJWT<T>): Either<KJWTVerificationError, ByteArray> {
        return Either.fromNullable(dJWT.signature()).mapLeft { KJWTVerificationError.MissingSignature }.map { decodeString(it) }
    }

    companion object {
        fun signDigestWithPrivateKey(algorithm: JWSRSAAlgorithm, privateKey: RSAPrivateKey): SignEncodedJWT =
            signDigestWithGenericPrivateKey(algorithm, privateKey)
    }

    val keyGenSpec: RSAKeyGenParameterSpec // https://www.keylength.com/en/3/
}
@Serializable
object JWSRSA256Algorithm: JWSRSAAlgorithm {
    override val headerID: String = "RS256"
    override val algorithmName: String = "SHA256withRSA"
    override val keyGenSpec: RSAKeyGenParameterSpec = RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4)
    override val jwtCreator: (JWTKeyID?, JWT.Companion.JWTClaimSetBuilder.() -> Unit) -> JWT<JWSRSA256Algorithm> = JWT.Companion::rs256
}
@Serializable
object JWSRSA384Algorithm: JWSRSAAlgorithm {
    override val headerID: String = "RS384"
    override val algorithmName: String = "SHA384withRSA"
    override val keyGenSpec: RSAKeyGenParameterSpec = RSAKeyGenParameterSpec(3072, RSAKeyGenParameterSpec.F4)
    override val jwtCreator: (JWTKeyID?, JWT.Companion.JWTClaimSetBuilder.() -> Unit) -> JWT<JWSRSA384Algorithm> = JWT.Companion::rs384
}
@Serializable
object JWSRSA512Algorithm: JWSRSAAlgorithm {
    override val headerID: String = "RS512"
    override val algorithmName: String = "SHA512withRSA"
    override val keyGenSpec: RSAKeyGenParameterSpec = RSAKeyGenParameterSpec(3072, RSAKeyGenParameterSpec.F4)
    override val jwtCreator: (JWTKeyID?, JWT.Companion.JWTClaimSetBuilder.() -> Unit) -> JWT<JWSRSA512Algorithm> = JWT.Companion::rs512
}

sealed interface JWSECDSAAlgorithm: JWSAsymmetricAlgorithm<ECPublicKey, ECPrivateKey> {
    val curve: String
    val signatureSize: Int

    suspend fun <T: JWSECDSAAlgorithm>sign(jwt: JWT<T>, signDigest: SignEncodedJWT): Either<KJWTSignError, SignedJWT<T>> {
        return either<KJWTSignError, ByteArray> {
            val encoded = Either.catch { jwt.encode() }.mapLeft { KJWTSignError.SigningError(it) }.bind()
            val signedData = signDigest(encoded).bind()
            derToJOSE(signedData, jwt.header.algorithm.signatureSize).mapLeft { KJWTSignError.SigningError(it) }.bind()
        }.map { sig ->
            SignedJWT(jwt, sig, jwt.header.algorithm)
        }
    }

    override fun <T: JWSAsymmetricAlgorithm<ECPublicKey, ECPrivateKey>>signature(dJWT: DecodedJWT<T>): Either<KJWTVerificationError, ByteArray> {
        return either.eager {
            val signatureJOSE = Either.fromNullable(dJWT.signature()).mapLeft { KJWTVerificationError.MissingSignature }.bind()
            val signatureDecoded = decodeString(signatureJOSE)
            joseToDER(signatureDecoded).mapLeft { KJWTVerificationError.InvalidJWT }.bind()
        }
    }

    companion object {

        fun signDigestWithPrivateKey(algorithm: JWSECDSAAlgorithm, privateKey: ECPrivateKey): SignEncodedJWT =
            signDigestWithGenericPrivateKey(algorithm, privateKey)
    }
}
@Serializable
object JWSES256Algorithm: JWSECDSAAlgorithm {
    override val headerID: String = "ES256"
    override val algorithmName: String = "SHA256withECDSA"
    override val curve: String = "secp256r1"
    override val signatureSize: Int = 64
    override val jwtCreator: (JWTKeyID?, JWT.Companion.JWTClaimSetBuilder.() -> Unit) -> JWT<JWSES256Algorithm> = JWT.Companion::es256
}
@Serializable
object JWSES256KAlgorithm: JWSECDSAAlgorithm {
    override val headerID: String = "ES256K"
    override val algorithmName: String = "SHA256withECDSA"
    override val curve: String = "secp256k1"
    override val signatureSize: Int = 64
    override val jwtCreator: (JWTKeyID?, JWT.Companion.JWTClaimSetBuilder.() -> Unit) -> JWT<JWSES256KAlgorithm> = JWT.Companion::es256k
}
@Serializable
object JWSES384Algorithm: JWSECDSAAlgorithm {
    override val headerID: String = "ES384"
    override val algorithmName: String = "SHA384withECDSA"
    override val curve: String = "secp384r1"
    override val signatureSize: Int = 96
    override val jwtCreator: (JWTKeyID?, JWT.Companion.JWTClaimSetBuilder.() -> Unit) -> JWT<JWSES384Algorithm> = JWT.Companion::es384
}
@Serializable
object JWSES512Algorithm: JWSECDSAAlgorithm {
    override val headerID: String = "ES512"
    override val algorithmName: String = "SHA512withECDSA"
    override val curve: String = "secp521r1"
    override val signatureSize: Int = 132
    override val jwtCreator: (JWTKeyID?, JWT.Companion.JWTClaimSetBuilder.() -> Unit) -> JWT<JWSES512Algorithm> = JWT.Companion::es512
}

val AllAlgorithms = setOf(
    JWSHMAC256Algorithm,
    JWSHMAC384Algorithm,
    JWSHMAC512Algorithm,
    JWSRSA256Algorithm,
    JWSRSA384Algorithm,
    JWSRSA512Algorithm,
    JWSES256Algorithm,
    JWSES256KAlgorithm,
    JWSES384Algorithm,
    JWSES512Algorithm,
)

private fun <T: JWSAsymmetricAlgorithm<PubK, PrivK>, PubK: PublicKey, PrivK: PrivateKey>signDigestWithGenericPrivateKey(algorithm: JWSAsymmetricAlgorithm<PubK, PrivK>, privateKey: PrivK): SignEncodedJWT = { encoded ->
    Either.catch {
        val data = encoded.toByteArray(Charsets.UTF_8)
        val signer = Signature.getInstance(algorithm.algorithmName)
        signer.initSign(privateKey, null)
        signer.update(data)
        signer.sign()
    }.mapLeft { KJWTSignError.SigningError(it) }
}

inline fun <reified T: JWSAlgorithm>algorithm(): T {
    return when (typeOf<T>()) {
        (typeOf<JWSHMAC256Algorithm>()) -> JWSHMAC256Algorithm as T
        (typeOf<JWSHMAC384Algorithm>()) -> JWSHMAC384Algorithm as T
        (typeOf<JWSHMAC512Algorithm>()) -> JWSHMAC512Algorithm as T
        (typeOf<JWSRSA256Algorithm>()) -> JWSRSA256Algorithm as T
        (typeOf<JWSRSA384Algorithm>()) -> JWSRSA384Algorithm as T
        (typeOf<JWSRSA512Algorithm>()) -> JWSRSA512Algorithm as T
        (typeOf<JWSES256Algorithm>()) -> JWSES256Algorithm as T
        (typeOf<JWSES256KAlgorithm>()) -> JWSES256KAlgorithm as T
        (typeOf<JWSES384Algorithm>()) -> JWSES384Algorithm as T
        (typeOf<JWSES512Algorithm>()) -> JWSES512Algorithm as T
        else -> {
            throw IllegalArgumentException("unknown algorithm: ${typeOf<T>()}")
        }
    }
}

fun derToJOSE(derSignature: ByteArray, outputLength: Int): Either<Throwable, ByteArray> {
    if (derSignature.size < 8 || derSignature[0].toInt() != 0x30)
        return SignatureException("Invalid ECDSA signature format1").left()

    val offset = when {
        derSignature[1].toInt() > 0     -> 2
        derSignature[1] == 0x81.toByte() -> 3 // two byte length
        else -> return SignatureException("Invalid ECDSA signature format2").left()
    }

    val rLength: Byte = derSignature[offset + 1]
    var i = rLength.toInt()
    while ((i > 0) && (derSignature[(offset + 2 + rLength) - i].toInt() == 0)) {
        i -= 1
    }

    val sLength: Byte = derSignature[offset + 2 + rLength + 1]
    var j = sLength.toInt()
    while ((j > 0) && (derSignature[(offset + 2 + rLength + 2 + sLength) - j].toInt() == 0)) {
        j -= 1
    }

    val rawLen: Int = i.coerceAtLeast(j).coerceAtLeast(outputLength / 2)

    if ((derSignature[offset - 1].toInt() and 0xff) != derSignature.size - offset ||
        (derSignature[offset - 1].toInt() and 0xff) != 2 + rLength + 2 + sLength ||
        derSignature[offset].toInt() != 2 ||
        derSignature[offset + 2 + rLength].toInt() != 2)
        return SignatureException("Invalid ECDSA signature format3").left()

    val concatSignature = ByteArray(2 * rawLen)
    System.arraycopy(derSignature, (offset + 2 + rLength) - i, concatSignature, rawLen - i, i)
    System.arraycopy(
        derSignature,
        (offset + 2 + rLength + 2 + sLength) - j,
        concatSignature,
        2 * rawLen - j,
        j
    )
    return concatSignature.right()
}

internal fun joseToDER(signature: ByteArray): Either<Throwable, ByteArray> {
    var r = signature.slice(0 until signature.size / 2)
    var s = signature.slice(signature.size / 2 until signature.size)

    r = r.dropWhile { it == 0.toByte() }
    if (r.isNotEmpty() && r[0] < 0)
        r.plus(0.toByte())

    s = s.dropWhile { it == 0.toByte() }
    if (s.isNotEmpty() && s[0] < 0)
        s.plus(0.toByte())

    val signatureLength = 2 + r.size + 2 + s.size

    if (signatureLength > 255)
        return SignatureException("Invalid ECDSA signature format").left()

    val signatureDER = mutableListOf<Byte>()
    signatureDER += 0x30.toByte()
    if (signatureLength >= 128)
        signatureDER += 0x81.toByte()

    signatureDER += signatureLength.toByte()
    signatureDER += 2.toByte()
    signatureDER += r.size.toByte()
    signatureDER += r

    signatureDER += 2.toByte()
    signatureDER += s.size.toByte()
    signatureDER += s

    return signatureDER.toByteArray().right()
}