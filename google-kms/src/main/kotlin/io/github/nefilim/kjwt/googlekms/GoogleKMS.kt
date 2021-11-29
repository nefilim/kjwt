package io.github.nefilim.kjwt.googlekms

import arrow.core.Either
import com.google.cloud.kms.v1.AsymmetricSignRequest
import com.google.cloud.kms.v1.CryptoKeyVersion
import com.google.cloud.kms.v1.Digest
import com.google.cloud.kms.v1.KeyManagementServiceGrpcKt
import com.google.protobuf.ByteString
import io.github.nefilim.kjwt.JWSECDSAAlgorithm
import io.github.nefilim.kjwt.JWSRSAAlgorithm
import io.github.nefilim.kjwt.JWT
import io.github.nefilim.kjwt.JWTSignError
import io.github.nefilim.kjwt.SignEncodedJWT
import io.github.nefilim.kjwt.SignedJWT
import io.grpc.*
import java.security.MessageDigest

private suspend fun signEncodedJWTWithKMS(
    stub: KeyManagementServiceGrpcKt.KeyManagementServiceCoroutineStub,
    cryptoKeyVersion: CryptoKeyVersion,
    headers: Metadata,
): SignEncodedJWT = { encoded ->
    Either.catch {
        val digest = ByteString.copyFrom(sha256(encoded))
        stub.asymmetricSign(
            AsymmetricSignRequest.newBuilder()
                .setName(cryptoKeyVersion.name)
                .setDigest(Digest.newBuilder().setSha256(digest).build())
                .build(),
            headers
        ).signature.toByteArray()
    }.mapLeft { JWTSignError.SigningError(it) }
}

suspend fun <T: JWSECDSAAlgorithm> JWT<T>.signWithKMS(
    stub: KeyManagementServiceGrpcKt.KeyManagementServiceCoroutineStub,
    cryptoKeyVersion: ECCryptoKeyVersion,
    headers: Metadata,
): Either<JWTSignError, SignedJWT<T>> {
    return this.header.algorithm.sign(this, signEncodedJWTWithKMS(stub, cryptoKeyVersion.key, headers))
}

suspend fun <T: JWSRSAAlgorithm> JWT<T>.signWithKMS(
    stub: KeyManagementServiceGrpcKt.KeyManagementServiceCoroutineStub,
    cryptoKeyVersion: RSACryptoKeyVersion,
    headers: Metadata,
): Either<JWTSignError, SignedJWT<T>> {
    return this.header.algorithm.sign(this, signEncodedJWTWithKMS(stub, cryptoKeyVersion.key, headers))
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