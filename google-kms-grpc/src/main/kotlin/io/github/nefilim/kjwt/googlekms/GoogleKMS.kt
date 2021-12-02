package io.github.nefilim.kjwt.googlekms

import arrow.core.Either
import arrow.core.computations.either
import arrow.core.left
import com.google.cloud.kms.v1.CryptoKey
import com.google.cloud.kms.v1.CryptoKeyVersion
import com.google.cloud.kms.v1.KeyManagementServiceGrpcKt
import com.google.cloud.kms.v1.asymmetricSignRequest
import com.google.cloud.kms.v1.digest
import com.google.cloud.kms.v1.getPublicKeyRequest
import com.google.cloud.kms.v1.listCryptoKeyVersionsRequest
import com.google.cloud.kms.v1.listCryptoKeysRequest
import com.google.protobuf.ByteString
import io.github.nefilim.kjwt.JWSECDSAAlgorithm
import io.github.nefilim.kjwt.JWSRSAAlgorithm
import io.github.nefilim.kjwt.JWT
import io.github.nefilim.kjwt.JWTKeyID
import io.github.nefilim.kjwt.KJWTSignError
import io.github.nefilim.kjwt.SignEncodedJWT
import io.github.nefilim.kjwt.SignedJWT
import io.github.nefilim.kjwt.jwtEncodeBytes
import io.grpc.Metadata
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.PublicKey
import java.security.spec.X509EncodedKeySpec
import java.util.*

private suspend fun signEncodedJWTWithKMS(
    kmsService: KeyManagementServiceGrpcKt.KeyManagementServiceCoroutineStub,
    cryptoKeyVersion: CryptoKeyVersion,
    headers: Metadata,
): SignEncodedJWT = { encoded ->
    Either.catch {
        val digestBytes = ByteString.copyFrom(sha256(encoded))
        kmsService.asymmetricSign(
            asymmetricSignRequest {
                name = cryptoKeyVersion.name
                digest = digest { sha256 = digestBytes }
            },
            headers
        ).signature.toByteArray()
    }.mapLeft { KJWTSignError.SigningError(it) }
}

suspend fun <T: JWSECDSAAlgorithm> JWT<T>.signWithKMS(
    kmsService: KeyManagementServiceGrpcKt.KeyManagementServiceCoroutineStub,
    cryptoKeyVersion: ECCryptoKeyVersion,
    headers: Metadata,
): Either<KJWTSignError, SignedJWT<T>> {
    return this.header.algorithm.sign(this, signEncodedJWTWithKMS(kmsService, cryptoKeyVersion.key, headers))
}

suspend fun <T: JWSRSAAlgorithm> JWT<T>.signWithKMS(
    kmsService: KeyManagementServiceGrpcKt.KeyManagementServiceCoroutineStub,
    cryptoKeyVersion: RSACryptoKeyVersion,
    headers: Metadata,
): Either<KJWTSignError, SignedJWT<T>> {
    return this.header.algorithm.sign(this, signEncodedJWTWithKMS(kmsService, cryptoKeyVersion.key, headers))
}

internal val GOOGLE_REQUEST_HEADER = Metadata.Key.of("x-goog-request-params", Metadata.ASCII_STRING_MARSHALLER)
private val GoogleLocationRegex = "projects/([a-z0-9-_]+)/locations/([a-z0-9-_]+)".toRegex()

// projects/mycoolstuff/locations/us-east1/keyRings/thekeyring
fun kmsParentLocationHeader(resourceName: String, metadata: Metadata = Metadata()): Metadata {
    GoogleLocationRegex.find(resourceName)?.groupValues?.let {
        metadata.put(GOOGLE_REQUEST_HEADER, "parent=projects/${it[1]}/locations/${it[2]}")
    }
    return metadata
}

sealed interface KMSError {
    object UnsupportedAlgorithm: KMSError
    data class InvalidKey(val cause: Throwable): KMSError
    data class GRPCError(val cause: Throwable): KMSError
    data class InvalidHashText(val cause: Throwable): KMSError
    data class MissingPublicKey(val signingKeyID: JWTKeyID): KMSError
}

suspend fun listKeys(
    kmsService: KeyManagementServiceGrpcKt.KeyManagementServiceCoroutineStub,
    keyringResourceName: String,
    headers: Metadata = kmsParentLocationHeader(keyringResourceName)
): Either<KMSError, List<CryptoKey>> {
    return Either.catch {
        kmsService.listCryptoKeys(
            listCryptoKeysRequest {
                parent = keyringResourceName
            },
            headers
        ).cryptoKeysList.toList().filterNotNull()
    }.mapLeft { KMSError.GRPCError(it) }
}

suspend fun listKeyVersions(
    kmsService: KeyManagementServiceGrpcKt.KeyManagementServiceCoroutineStub,
    keyResourceName: String,
    headers: Metadata = kmsParentLocationHeader(keyResourceName)
): Either<KMSError, List<CryptoKeyVersion>> {
    return Either.catch {
        kmsService.listCryptoKeyVersions(
            listCryptoKeyVersionsRequest {
                parent = keyResourceName
            },
            headers
        ).cryptoKeyVersionsList.toList()
    }.mapLeft { KMSError.GRPCError(it) }
}

suspend fun getPublicKey(
    kmsService: KeyManagementServiceGrpcKt.KeyManagementServiceCoroutineStub,
    keyVersion: CryptoKeyVersion,
    headers: Metadata = kmsParentLocationHeader(keyVersion.name)
): Either<KMSError, PublicKey> {
    return getPublicKey(kmsService, keyVersion.name, headers)
}

suspend fun getPublicKey(
    kmsService: KeyManagementServiceGrpcKt.KeyManagementServiceCoroutineStub,
    keyVersionResourceName: String,
    headers: Metadata = kmsParentLocationHeader(keyVersionResourceName)
): Either<KMSError, PublicKey> {
    return either {
        val key = Either.catch {
            kmsService.getPublicKey(
                getPublicKeyRequest {
                    name = keyVersionResourceName
                },
                headers
            )
        }.mapLeft { KMSError.GRPCError(it) }.bind()
        when {
            SupportedRSAAlgorithms.contains(key.algorithm) -> pemToPublicKey(key.pem, "RSA")
            SupportedECAlgorithms.contains(key.algorithm) -> pemToPublicKey(key.pem, "EC")
            else -> KMSError.UnsupportedAlgorithm.left()
        }.bind()
    }
}

private val SupportedRSAAlgorithms = setOf(
    CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PKCS1_2048_SHA256,
    CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PKCS1_4096_SHA512,
)

private val SupportedECAlgorithms = setOf(
    CryptoKeyVersion.CryptoKeyVersionAlgorithm.EC_SIGN_P256_SHA256,
    CryptoKeyVersion.CryptoKeyVersionAlgorithm.EC_SIGN_SECP256K1_SHA256,
    CryptoKeyVersion.CryptoKeyVersionAlgorithm.EC_SIGN_P384_SHA384,
)

// replace with BC?
private fun pemToPublicKey(pem: String, algo: String): Either<KMSError, PublicKey> {
    return Either.catch {
        val raw = pem.replace("-----BEGIN PUBLIC KEY-----\n", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replace("\n", "")
        val encoded = Base64.getDecoder().decode(raw)

        val keyFactory = KeyFactory.getInstance(algo)
        val keySpec = X509EncodedKeySpec(encoded)
        keyFactory.generatePublic(keySpec)
    }.mapLeft {
        KMSError.InvalidKey(it)
    }
}

// TODO replace runtime invariant checking with compile time type checking
data class RSACryptoKeyVersion(
    val key: CryptoKeyVersion
) {
    init {
        require(key.isInitialized && key.algorithm.name.startsWith("RSA_SIGN_PKCS1"))
    }
}

data class ECCryptoKeyVersion(
    val key: CryptoKeyVersion
) {
    init {
        require(key.isInitialized && key.algorithm.name.startsWith("EC_SIGN"))
    }
}

private fun sha256(data: String): ByteArray {
    val digest = MessageDigest.getInstance("SHA-256")
    return digest.digest(data.toByteArray(Charsets.UTF_8))
}

fun hashedJWTKeyID(text: String): Either<KMSError, JWTKeyID> {
    return Either.catch {
        val md = MessageDigest.getInstance("SHA-1")
        JWTKeyID(jwtEncodeBytes(md.digest(text.toByteArray(Charsets.UTF_8))))
    }.mapLeft { KMSError.InvalidHashText(it) }
}