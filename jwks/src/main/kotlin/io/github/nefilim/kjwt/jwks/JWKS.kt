package io.github.nefilim.kjwt.jwks

import arrow.core.*
import arrow.core.computations.either
import io.github.nefilim.kjwt.*
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.FlowCollector
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onCompletion
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.isActive
import kotlinx.coroutines.withContext
import kotlinx.serialization.*
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.jsonArray
import java.math.BigInteger
import java.net.URL
import java.security.AlgorithmParameters
import java.security.GeneralSecurityException
import java.security.KeyFactory
import java.security.PublicKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.security.spec.RSAPublicKeySpec
import java.util.*
import kotlin.coroutines.CoroutineContext
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds
import kotlin.time.DurationUnit
import kotlin.time.ExperimentalTime
import mu.KotlinLogging

private val logger = KotlinLogging.logger {  }

@Serializable
data class JWK<T: JWSAlgorithm>(
    @SerialName("kid") val keyID: JWTKeyID,
    @SerialName("alg") @Serializable(JWSAlgorithmSerializer::class) val algorithm: T,
    @SerialName("kty") val keyType: String? = null,
    val use: Use? = null,
    @SerialName("key_ops") val keyOps: KeyOperations? = null,
    @SerialName("n") val publicKeyModulus: String? = null,
    @SerialName("e") val publicKeyExponent: String? = null,
    // we don't want to include empty fields for these, otherwise the lua-resty-oidc craps out
    @SerialName("x5t") val x509CertificateThumbprint: String? = null,
    @SerialName("x5c") val x509CertificateChain: List<String>? = null,
    @SerialName("curve") val curve: String? = null,
    @SerialName("x") val x: String? = null,
    @SerialName("y") val y: String? = null,
) {
    companion object {
        @Serializable
        enum class Use {
            @SerialName("sig") SIGNATURE,
            @SerialName("enc") ENCRYPTION,
        }

        @Serializable
        enum class KeyOperations {
            @SerialName("sign") SIGN,
            @SerialName("verify") VERIFY,
            @SerialName("encrypt") ENCRYPT,
            @SerialName("decrypt") DECRYPT,
            @SerialName("wrapKey") WRAPKEY,
            @SerialName("unwrapKey") UNWRAPKEY,
            @SerialName("deriveKey") DERIVEKEY,
            @SerialName("deriveBits") DERIVEBITS,
        }

        @JvmName("buildRSAKey")
        fun <T: JWSRSAAlgorithm>JWK<T>.buildKey(): Either<JWKError, RSAPublicKey> {
            return this.build()
        }

        @JvmName("buildECKey")
        fun <T: JWSECDSAAlgorithm>JWK<T>.buildKey(): Either<JWKError, ECPublicKey> {
            return this.build()
        }
    }

    // this won't cast to the actual type parameter unless it's reified??
    inline fun <reified P: PublicKey>build(): Either<JWKError, P> {
        return when (algorithm) {
            is JWSECDSAAlgorithm -> {
                try {
                    val keyFactory = KeyFactory.getInstance("EC")
                    val ecPoint = ECPoint(
                        BigInteger(Base64.getUrlDecoder().decode(x)),
                        BigInteger(Base64.getUrlDecoder().decode(y))
                    )
                    val algorithmParameters = AlgorithmParameters.getInstance("EC")
                    algorithmParameters.init(ECGenParameterSpec(algorithm.curve))
                    val ecParameterSpec = algorithmParameters.getParameterSpec(ECParameterSpec::class.java)
                    val ecPublicKeySpec = ECPublicKeySpec(ecPoint, ecParameterSpec)
                    (keyFactory.generatePublic(ecPublicKeySpec) as P).right()
                } catch (e: ClassCastException) {
                    JWKError.AlgorithmKeyMismatch.left()
                } catch (e: GeneralSecurityException) {
                    JWKError.InvalidKey(e).left()
                } catch (e: Exception) {
                    JWKError.Exceptionally(e).left()
                }
            }
            is JWSRSAAlgorithm -> {
                try {
                    val kf = KeyFactory.getInstance("RSA")
                    val modulus = BigInteger(1, Base64.getUrlDecoder().decode(publicKeyModulus))
                    val exponent = BigInteger(1, Base64.getUrlDecoder().decode(publicKeyExponent))
                    (kf.generatePublic(RSAPublicKeySpec(modulus, exponent)) as P).right()
                } catch (e: ClassCastException) {
                    JWKError.AlgorithmKeyMismatch.left()
                } catch (e: GeneralSecurityException) {
                    JWKError.InvalidKey(e).left()
                } catch (e: Exception) {
                    JWKError.Exceptionally(e).left()
                }
            }
            else ->
                JWKError.UnsupportedAlgorithm(algorithm).left()
        }
    }
}

@Serializable
data class JWKS(
    @Serializable(JWKListSerializer::class) val keys: List<JWK<JWSAlgorithm>>
)

object JWKListSerializer: KSerializer<List<JWK<JWSAlgorithm>>> {
    override fun deserialize(decoder: Decoder): List<JWK<JWSAlgorithm>> {
        return with(decoder as JsonDecoder) {
            decodeJsonElement().jsonArray.mapNotNull {
                try {
                    json.decodeFromJsonElement(JWK.serializer(PolymorphicSerializer(JWSAlgorithm::class)), it)
                } catch (e: Exception) {
                    when (e) {
                        is SerializationException, is UnsupportedAlgorithmException -> {
                            logger.warn { "ignoring JWK with deserialization problem $e " }
                            null
                        }
                        else ->
                            throw e
                    }
                }
            }
        }
    }

    private val listSerializer = ListSerializer(JWK.serializer(PolymorphicSerializer(JWSAlgorithm::class)))
    override val descriptor: SerialDescriptor = listSerializer.descriptor

    override fun serialize(encoder: Encoder, value: List<JWK<JWSAlgorithm>>) {
        listSerializer.serialize(encoder, value)
    }
}

sealed interface JWKError {
    object AlgorithmKeyMismatch: JWKError
    data class InvalidKey(val cause: Throwable): JWKError
    data class UnsupportedAlgorithm(val alg: JWSAlgorithm): JWKError
    data class Exceptionally(val cause: Throwable): JWKError
    data class NoSuchKey(val keyID: JWTKeyID): JWKError
}

fun interface JWKSProvider<P: PublicKey> {
    suspend operator fun invoke(): Either<JWKError, Map<JWTKeyID, P>>
}

suspend fun <P: PublicKey>JWKSProvider<P>.getKey(keyID: JWTKeyID): Either<JWKError, P> {
    return this().flatMap {
        Either.fromNullable(it[keyID]).mapLeft { JWKError.NoSuchKey(keyID) }
    }
}

object WellKnownJWKSProvider {
    data class WellKnownContext(
        val url: String,
        val connectTimeout: Duration = 30.seconds,
        val readTimeout: Duration = 30.seconds,
        val headers: Map<String, String> = emptyMap(),
    ) {
        val wellKnownURL = URL(url)

        companion object {
            fun standardsWellKnownURL(url: String): String = "${url.trimEnd('/')}/.well-known/jwks.json"
        }
    }

    val json = Json {
        isLenient = true
        ignoreUnknownKeys = true
    }

    suspend fun downloadJWKS(context: WellKnownContext, coroutineContext: CoroutineContext = Dispatchers.IO): Either<JWKError, String> {
        return withContext(coroutineContext) {
            Either.catch {
                val c = context.wellKnownURL.openConnection()
                c.connectTimeout = context.connectTimeout.toInt(DurationUnit.MILLISECONDS)
                c.readTimeout = context.readTimeout.toInt(DurationUnit.MILLISECONDS)

                for ((key, value) in context.headers.entries) {
                    c.setRequestProperty(key, value)
                }

                Scanner(c.getInputStream()).use {
                    it.useDelimiter("\\A")
                    if (it.hasNext()) it.next() else throw IllegalArgumentException("no content at ${context.wellKnownURL}")
                }
            }.mapLeft { JWKError.Exceptionally(it) }
        }
    }

    inline fun <reified P: PublicKey>WellKnownContext.getJWKProvider(
        crossinline jwksJSONProvider: suspend (WellKnownContext, CoroutineContext) -> Either<JWKError, String> = ::downloadJWKS,
        coroutineContext: CoroutineContext = Dispatchers.IO,
    ): JWKSProvider<P> = JWKSProvider {
        val context = this
        either {
            val json = jwksJSONProvider(context, coroutineContext).bind()
            val jwks = Either.catch {
//                WellKnownJWKSProvider.json.decodeFromString(JWKS.serializer(PolymorphicSerializer(JWSAlgorithm::class)), json)
                WellKnownJWKSProvider.json.decodeFromString(JWKS.serializer(), json)
//                WellKnownJWKSProvider.json.decodeFromString(JWKListSerializer, json)
            }.mapLeft { JWKError.Exceptionally(it) }.bind()
            jwks.keys.map { jwk -> jwk.build<P>().map { jwk.keyID to it } }.sequenceEither().bind().toMap()
        }
    }
}

object CachedJWKSProvider {
    @OptIn(ExperimentalTime::class)
    suspend fun <P: PublicKey>JWKSProvider<P>.cached(
        refreshInterval: Duration = 5.minutes,
        coroutineScope: CoroutineScope,
        onCompletion: FlowCollector<Either<JWKError, Map<JWTKeyID, P>>>.(Throwable?) -> Unit = { },
    ): JWKSProvider<P> {
        val parentProvider = this
        val msf = MutableStateFlow(parentProvider())
        val stateFlow = msf.asStateFlow()
        flow {
            while (currentCoroutineContext().isActive) {
                delay(refreshInterval)
                emit(parentProvider())
            }
        }
            .onEach { msf.emit(it) }
            .onCompletion { onCompletion(it) }
            .launchIn(coroutineScope)

        return JWKSProvider {
            stateFlow.value
        }
    }
}