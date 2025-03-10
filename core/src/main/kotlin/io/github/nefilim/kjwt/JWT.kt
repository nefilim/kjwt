package io.github.nefilim.kjwt

import arrow.core.Either
import arrow.core.Option
import arrow.core.raise.Raise
import arrow.core.raise.catch
import arrow.core.raise.either
import arrow.core.raise.ensure
import kotlinx.serialization.PolymorphicSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull
import java.time.Clock
import java.time.Instant
import java.util.*

enum class JOSEType(val id: String) {
    JWT("JWT")
}

@JvmInline
@Serializable
value class JWTKeyID(val id: String)
fun String?.toJWTKeyID(): JWTKeyID? = this?.let { JWTKeyID(it)}

@Serializable
data class JOSEHeader<T: JWSAlgorithm>(
    @SerialName("alg") @Serializable(JWSAlgorithmSerializer::class) val algorithm: T,
    @SerialName("typ") @Serializable(JOSETypeSerializer::class) val type: JOSEType? = null,
    @SerialName("kid") val keyID: JWTKeyID? = null,
) {
    fun toJSON(): String {
        return if (keyID != null && keyID.id.isNotBlank())
            """{"alg":"${algorithm.headerID}","typ":"${JOSEType.JWT}","kid":"${keyID.id}"}"""
        else
            """{"alg":"${algorithm.headerID}","typ":"${JOSEType.JWT}"}"""
    }
}

interface JWTClaims {
    fun claimValue(name: String): Option<String>
    fun claimValueAsInt(name: String): Option<Int>
    fun claimValueAsLong(name: String): Option<Long>
    fun claimValueAsBoolean(name: String): Option<Boolean>
    fun claimValueAsList(name: String): List<String>
    fun claimNames(): Set<String>

    fun keyID(): Option<JWTKeyID>
    fun issuer(): Option<String>
    fun subject(): Option<String>
    fun audience(): Option<String>
    fun expiresAt(): Option<Instant>
    fun notBefore(): Option<Instant>
    fun issuedAt(): Option<Instant>
    fun jwtID(): Option<String>
}

class JWT<T: JWSAlgorithm> private constructor(
    val header: JOSEHeader<T>,
    private val claimSet: Map<String, JsonElement>
): JWTClaims {
    companion object {
        class JWTClaimSetBuilder internal constructor() {
            private val values: MutableMap<String, JsonElement> = LinkedHashMap(10)

            fun claim(name: String, value: String) {
                values[name] = JsonPrimitive(value)
            }
            fun claim(name: String, value: Int) {
                values[name] = JsonPrimitive(value)
            }
            fun claim(name: String, value: Long) {
                values[name] = JsonPrimitive(value)
            }
            fun claim(name: String, value: Boolean) {
                values[name] = JsonPrimitive(value)
            }
            fun claim(name: String, value: List<String>) {
                values[name] = JsonArray(value.map { JsonPrimitive(it) })
            }

            fun issuer(i: String) = claim("iss", i)
            fun subject(s: String) = claim("sub", s)
            fun audience(a: String) = claim("aud", a)
            fun expiresAt(d: Instant) = claim("exp", d.jwtNumericDate())
            fun notBefore(d: Instant) = claim("nbf", d.jwtNumericDate())
            fun issuedAt(d: Instant) = claim("iat", d.jwtNumericDate())
            fun issuedNow(clock: Clock = Clock.systemUTC()) = issuedAt(clock.instant())
            fun jwtID(id: String) = claim("jti", id)

            fun build(): Map<String, JsonElement> = Collections.unmodifiableMap(values)
        }
        val format = Json
        private val prettyFormat = Json {
            prettyPrint = true
        }

        internal fun es256WithoutTypeHeader(claims: JWTClaimSetBuilder.() -> Unit): JWT<JWSES256Algorithm> = buildJWT(JOSEHeader(JWSES256Algorithm), claims)
        fun es256(keyID: JWTKeyID? = null, claims: JWTClaimSetBuilder.() -> Unit): JWT<JWSES256Algorithm> = buildJWT(JOSEHeader(JWSES256Algorithm, JOSEType.JWT, keyID), claims)
        fun es256k(keyID: JWTKeyID? = null, claims: JWTClaimSetBuilder.() -> Unit): JWT<JWSES256KAlgorithm> = buildJWT(JOSEHeader(JWSES256KAlgorithm, JOSEType.JWT, keyID), claims)
        fun es384(keyID: JWTKeyID? = null, claims: JWTClaimSetBuilder.() -> Unit): JWT<JWSES384Algorithm> = buildJWT(JOSEHeader(JWSES384Algorithm, JOSEType.JWT, keyID), claims)
        fun es512(keyID: JWTKeyID? = null, claims: JWTClaimSetBuilder.() -> Unit): JWT<JWSES512Algorithm> = buildJWT(JOSEHeader(JWSES512Algorithm, JOSEType.JWT, keyID), claims)

        fun rs256(keyID: JWTKeyID? = null, claims: JWTClaimSetBuilder.() -> Unit): JWT<JWSRSA256Algorithm> = buildJWT(JOSEHeader(JWSRSA256Algorithm, JOSEType.JWT, keyID), claims)
        fun rs384(keyID: JWTKeyID? = null, claims: JWTClaimSetBuilder.() -> Unit): JWT<JWSRSA384Algorithm> = buildJWT(JOSEHeader(JWSRSA384Algorithm, JOSEType.JWT, keyID), claims)
        fun rs512(keyID: JWTKeyID? = null, claims: JWTClaimSetBuilder.() -> Unit): JWT<JWSRSA512Algorithm> = buildJWT(JOSEHeader(JWSRSA512Algorithm, JOSEType.JWT, keyID), claims)

        fun hs256(keyID: JWTKeyID? = null, claims: JWTClaimSetBuilder.() -> Unit): JWT<JWSHMAC256Algorithm> = buildJWT(JOSEHeader(JWSHMAC256Algorithm, JOSEType.JWT, keyID), claims)
        fun hs384(keyID: JWTKeyID? = null, claims: JWTClaimSetBuilder.() -> Unit): JWT<JWSHMAC384Algorithm> = buildJWT(JOSEHeader(JWSHMAC384Algorithm, JOSEType.JWT, keyID), claims)
        fun hs512(keyID: JWTKeyID? = null, claims: JWTClaimSetBuilder.() -> Unit): JWT<JWSHMAC512Algorithm> = buildJWT(JOSEHeader(JWSHMAC512Algorithm, JOSEType.JWT, keyID), claims)

        private fun <T: JWSAlgorithm>buildJWT(header: JOSEHeader<T>, claims: JWTClaimSetBuilder.() -> Unit): JWT<T> {
            val builder = JWTClaimSetBuilder()
            builder.claims()

            return JWT(header, builder.build())
        }

        fun decode(jwt: String): Either<KJWTVerificationError, DecodedJWT<out JWSAlgorithm>> {
            return either {
                val parts = jwt.split(".")
                ensure(!(parts.size < 2 || parts.size > 3)) { KJWTVerificationError.InvalidJWT }

                val h = Either.catch {
                    format.decodeFromString(JOSEHeader.serializer(PolymorphicSerializer(JWSAlgorithm::class)), jwtDecodeString(parts[0]))
                }.mapLeft {
                    println(it)
                    KJWTVerificationError.AlgorithmMismatch }.bind()
                val claims = Either.catch { format.parseToJsonElement(jwtDecodeString(parts[1])) }.mapLeft { KJWTVerificationError.InvalidJWT }.bind()
                val claimsMap = Either.catch { (claims as JsonObject) }.mapLeft { KJWTVerificationError.EmptyClaims }.bind()

                DecodedJWT(JWT(h, claimsMap), parts)
            }
        }

        fun <T: JWSAlgorithm>decodeT(jwt: String, algorithm: T): Either<KJWTVerificationError, DecodedJWT<T>> {
            return either {
                val decodedJWT = decode(jwt).bind()
                ensure(decodedJWT.jwt.header.algorithm == algorithm) { KJWTVerificationError.AlgorithmMismatch }
                @Suppress("UNCHECKED_CAST")
                Either.catch { decodedJWT as DecodedJWT<T> }.mapLeft { KJWTVerificationError.AlgorithmMismatch }.bind()
            }
        }
    }

    fun encode(): String {
        return json().joinToString(".") {
            jwtEncodeBytes(it.toByteArray(Charsets.UTF_8))
        }
    }

    private fun json(format: Json = Companion.format): List<String> {
        return listOf(
            header.toJSON(),
            format.encodeToString(buildJsonObject {
                claimSet.forEach { (t, u) -> put(t, u) }
            }),
        )
    }

    override fun toString(): String {
        return json(prettyFormat).joinToString("\n")
    }

    override fun claimValue(name: String): Option<String> = Option.fromNullable(claimSet[name]?.jsonPrimitive?.contentOrNull)
    override fun claimValueAsInt(name: String): Option<Int> = Option.fromNullable(claimSet[name]?.jsonPrimitive?.intOrNull)
    override fun claimValueAsLong(name: String): Option<Long> = Option.fromNullable(claimSet[name]?.jsonPrimitive?.longOrNull)
    override fun claimValueAsBoolean(name: String): Option<Boolean> = Option.fromNullable(claimSet[name]?.jsonPrimitive?.booleanOrNull)
    override fun claimValueAsList(name: String): List<String> = claimSet[name]?.jsonArray?.mapNotNull { (it as JsonPrimitive).contentOrNull?.trim() } ?: emptyList()
    override fun claimNames(): Set<String> = claimSet.keys

    override fun keyID(): Option<JWTKeyID> = Option.fromNullable(header.keyID)
    override fun issuer(): Option<String> = claimValue("iss")
    override fun subject(): Option<String> = claimValue("sub")
    override fun audience(): Option<String> = claimValue("aud")
    override fun expiresAt(): Option<Instant> = claimValueAsLong("exp").map { it.fromJWTNumericDate() }
    override fun notBefore(): Option<Instant> = claimValueAsLong("nbf").map { it.fromJWTNumericDate() }
    override fun issuedAt(): Option<Instant> = claimValueAsLong("iat").map { it.fromJWTNumericDate() }
    override fun jwtID(): Option<String> = claimValue("jti")

    // generated
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as JWT<T> // hmm ??

        if (header != other.header) return false
        if (claimSet != other.claimSet) return false

        return true
    }

    // generated
    override fun hashCode(): Int {
        var result = header.hashCode()
        result = 31 * result + claimSet.hashCode()
        return result
    }
}

data class DecodedJWT<T: JWSAlgorithm>(
    val jwt: JWT<T>,
    val parts: List<String>,
): JWTClaims by jwt {
    fun signature(): String? = parts.getOrNull(2)

    fun signedData(): String = parts[0] + "." + parts[1]
}

data class SignedJWT<T: JWSAlgorithm>(
    val jwt: JWT<T>,
    val signature: ByteArray,
    val algorithm: JWSAlgorithm,
) {
    val rendered: String = jwt.encode() + "." + jwtEncodeBytes(signature)
}

// https://datatracker.ietf.org/doc/html/rfc7519#section-2
internal fun Instant.jwtNumericDate(): Long = this.epochSecond
internal fun Long.fromJWTNumericDate(): Instant = Instant.ofEpochSecond(this, 0L)
fun jwtEncodeBytes(data: ByteArray): String = String(Base64.getUrlEncoder().encode(data)).trimEnd('=') // remove trailing '=' as per JWT spec
fun jwtDecodeString(data: String): String = String(Base64.getUrlDecoder().decode(data))
internal fun decodeString(data: String): ByteArray = Base64.getUrlDecoder().decode(data)
internal fun Raise<KJWTSignError>.stringToBytes(data: String, raise: () -> KJWTSignError): ByteArray =
    catch(
        block = { data.toByteArray(Charsets.UTF_8) },
        catch = { raise(raise()) }
    )