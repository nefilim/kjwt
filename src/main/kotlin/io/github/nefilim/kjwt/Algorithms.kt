package io.github.nefilim.kjwt

import arrow.core.Either
import arrow.core.computations.either
import arrow.core.flatMap
import arrow.core.left
import arrow.core.right
import kotlinx.serialization.Serializable
import java.security.PublicKey
import java.security.Signature
import java.security.SignatureException
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.RSAPrivateKey
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

sealed interface JWTSignError {
    object InvalidKey: JWTSignError
    object InvalidJWT: JWTSignError
    object KeyAlgorithmMismatch: JWTSignError
    data class SigningError(val cause: Throwable): JWTSignError
}

sealed interface JWTVerificationError {
    object InvalidJWT: JWTVerificationError
    object AlgorithmMismatch: JWTVerificationError
    object KeyAlgorithmMismatch: JWTVerificationError
    object BrokenSignature: JWTVerificationError
    object InvalidSignature: JWTVerificationError
    object MissingSignature: JWTVerificationError
    object EmptyClaims: JWTVerificationError
}

sealed interface JWSAlgorithm {
    val headerID: String
    val algorithmName: String
}
sealed interface JWSSymmetricAlgorithm: JWSAlgorithm {
    fun <T: JWSSymmetricAlgorithm>sign(jwt: JWT<T>, secret: String): Either<JWTSignError, SignedJWT<T>> {
        return either.eager<JWTSignError, ByteArray> {
            val nonBlankSecret = Either.conditionally(secret.isNotBlank(), { JWTSignError.InvalidKey }, { secret }).bind()
            val secretBytes = stringToBytes(nonBlankSecret).mapLeft { JWTSignError.InvalidKey }.bind()
            val dataToSign = stringToBytes(jwt.encode()).mapLeft { JWTSignError.InvalidJWT }.bind()
            Either.catch {
                val mac = Mac.getInstance(jwt.header.algorithm.algorithmName)
                mac.init(SecretKeySpec(secretBytes, jwt.header.algorithm.algorithmName))
                mac.doFinal(dataToSign)
            }.mapLeft { JWTSignError.SigningError(it) }.bind()
        }.map {
            SignedJWT(jwt, it, jwt.header.algorithm)
        }
    }
    fun <T: JWSSymmetricAlgorithm>verifySignature(dJWT: DecodedJWT<T>, secret: String): Either<JWTVerificationError, JWT<T>> {
        return either.eager<JWTVerificationError, JWT<T>> {
            val signature = Either.fromNullable(dJWT.signature()).mapLeft { JWTVerificationError.MissingSignature }.bind()
            val signedJWT = sign(dJWT.jwt, secret).mapLeft { JWTVerificationError.InvalidJWT }.bind()
            Either.conditionally(jwtEncodeBytes(signedJWT.signature) == signature, { JWTVerificationError.InvalidSignature }, { dJWT.jwt} ).bind()
        }
    }
}
sealed interface JWSAsymmetricAlgorithm: JWSAlgorithm {
    fun <T: JWSAsymmetricAlgorithm>verifySignature(
        dJWT: DecodedJWT<T>,
        key: PublicKey,
        signature: Either<JWTVerificationError, ByteArray>,
    ): Either<JWTVerificationError, JWT<T>> {
        val signer = Signature.getInstance(dJWT.jwt.header.algorithm.algorithmName)

        return either.eager<JWTVerificationError, Boolean> {
            Either.catch { signer.initVerify(key) }.mapLeft { JWTVerificationError.KeyAlgorithmMismatch }.bind()
            val dataToVerify = Either.catch { dJWT.signedData().toByteArray() }.mapLeft { JWTVerificationError.InvalidJWT }.bind()
            val sig = signature.bind()
            Either.catch { signer.update(dataToVerify) }.mapLeft { JWTVerificationError.BrokenSignature }.bind()
            Either.catch { signer.verify(sig) }.mapLeft { JWTVerificationError.BrokenSignature }.bind()
        }.flatMap {
            Either.conditionally(it, { JWTVerificationError.InvalidSignature }, { dJWT.jwt })
        }
    }
}

sealed interface JWSHMACAlgorithm: JWSSymmetricAlgorithm
@Serializable
object JWSHMAC256Algorithm: JWSHMACAlgorithm {
    override val headerID: String = "HS256"
    override val algorithmName: String = "HmacSHA256"
}
@Serializable
object JWSHMAC384Algorithm: JWSHMACAlgorithm {
    override val headerID: String = "HS384"
    override val algorithmName: String = "HmacSHA384"
}
@Serializable
object JWSHMAC512Algorithm: JWSHMACAlgorithm {
    override val headerID: String = "HS512"
    override val algorithmName: String = "HmacSHA512"
}

sealed interface JWSRSAAlgorithm: JWSAsymmetricAlgorithm {
    fun <T: JWSRSAAlgorithm>sign(jwt: JWT<T>, privateKey: RSAPrivateKey): Either<JWTSignError, SignedJWT<T>> {
        val encoded = jwt.encode()
        return Either.catch {
            val data = encoded.toByteArray(Charsets.UTF_8)
            val signer = Signature.getInstance(jwt.header.algorithm.algorithmName)
            signer.initSign(privateKey, null)
            signer.update(data)
            signer.sign()
        }.bimap({ JWTSignError.SigningError(it) }, { SignedJWT(jwt, it, jwt.header.algorithm) })
    }

    companion object {
        fun <T: JWSRSAAlgorithm>signature(dJWT: DecodedJWT<T>): Either<JWTVerificationError, ByteArray> {
            return Either.fromNullable(dJWT.signature()).mapLeft { JWTVerificationError.MissingSignature }.map { decodeString(it) }
        }
    }
}
@Serializable
object JWSRSA256Algorithm: JWSRSAAlgorithm {
    override val headerID: String = "RS256"
    override val algorithmName: String = "SHA256withRSA"
}
@Serializable
object JWSRSA384Algorithm: JWSRSAAlgorithm {
    override val headerID: String = "RS384"
    override val algorithmName: String = "SHA384withRSA"
}
@Serializable
object JWSRSA512Algorithm: JWSRSAAlgorithm {
    override val headerID: String = "RS512"
    override val algorithmName: String = "SHA512withRSA"
}

sealed interface JWSECDSAAlgorithm: JWSAsymmetricAlgorithm {
    val curve: String
    val signatureSize: Int

    fun <T: JWSECDSAAlgorithm>sign(jwt: JWT<T>, privateKey: ECPrivateKey): Either<JWTSignError, SignedJWT<T>> {
        val encoded = jwt.encode()
        return either.eager<JWTSignError, ByteArray> {
            val algorithm = jwt.header.algorithm as JWSECDSAAlgorithm
            val signedData = Either.catch {
                val data = encoded.toByteArray(Charsets.UTF_8)
                val signer = Signature.getInstance(algorithm.algorithmName)
                signer.initSign(privateKey, null)
                signer.update(data)
                signer.sign()
            }.mapLeft { JWTSignError.SigningError(it) }.bind()
            derToJOSE(signedData, algorithm.signatureSize).mapLeft { JWTSignError.SigningError(it) }.bind()
        }.map { sig ->
            SignedJWT(jwt, sig, jwt.header.algorithm)
        }
    }

    companion object {
        fun <T: JWSECDSAAlgorithm>signature(dJWT: DecodedJWT<T>): Either<JWTVerificationError, ByteArray> {
            return either.eager {
                val signatureJOSE = Either.fromNullable(dJWT.signature()).mapLeft { JWTVerificationError.MissingSignature }.bind()
                val signatureDecoded = decodeString(signatureJOSE)
                joseToDER(signatureDecoded).mapLeft { JWTVerificationError.InvalidJWT }.bind()
            }
        }
    }
}
@Serializable
object JWSES256Algorithm: JWSECDSAAlgorithm {
    override val headerID: String = "ES256"
    override val algorithmName: String = "SHA256withECDSA"
    override val curve: String = "secp256r1"
    override val signatureSize: Int = 64
}
@Serializable
object JWSES256KAlgorithm: JWSECDSAAlgorithm {
    override val headerID: String = "ES256K"
    override val algorithmName: String = "SHA256withECDSA"
    override val curve: String = "secp256k1"
    override val signatureSize: Int = 64
}
@Serializable
object JWSES384Algorithm: JWSECDSAAlgorithm {
    override val headerID: String = "ES384"
    override val algorithmName: String = "SHA384withECDSA"
    override val curve: String = "secp384r1"
    override val signatureSize: Int = 96
}
@Serializable
object JWSES512Algorithm: JWSECDSAAlgorithm {
    override val headerID: String = "ES512"
    override val algorithmName: String = "SHA512withECDSA"
    override val curve: String = "secp521r1"
    override val signatureSize: Int = 132
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

internal fun derToJOSE(derSignature: ByteArray, outputLength: Int): Either<Throwable, ByteArray> {
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