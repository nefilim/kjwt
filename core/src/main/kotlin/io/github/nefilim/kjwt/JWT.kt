package io.github.nefilim.kjwt

import arrow.core.Either
import arrow.core.Option
import arrow.core.left
import arrow.core.right
import kotlinx.serialization.PolymorphicSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull
import java.time.LocalDateTime
import java.time.ZoneOffset
import java.util.*

enum class JOSEType(val id: String) {
    JWT("JWT")
}

@Serializable
data class JOSEHeader<T: JWSAlgorithm>(
    @SerialName("alg") @Serializable(JWSAlgorithmSerializer::class) val algorithm: T,
    @SerialName("typ") val type: JOSEType,
    @SerialName("kid") val keyID: String? = null,
) {
    fun toJSON(): String {
        return if (keyID != null && keyID.isNotBlank())
            """{"alg":"${algorithm.headerID}","typ":"${JOSEType.JWT}","kid":"$keyID"}"""
        else
            """{"alg":"${algorithm.headerID}","typ":"${JOSEType.JWT}"}"""
    }
}

interface JWTClaims {
    fun claimValue(name: String): Option<String>
    fun claimValueAsInt(name: String): Option<Int>
    fun claimValueAsLong(name: String): Option<Long>
    fun claimValueAsBoolean(name: String): Option<Boolean>

    fun keyID(): Option<String>
    fun issuer(): Option<String>
    fun subject(): Option<String>
    fun audience(): Option<String>
    fun expiresAt(): Option<LocalDateTime>
    fun notBefore(): Option<LocalDateTime>
    fun issuedAt(): Option<LocalDateTime>
    fun jwtID(): Option<String>
}

class JWT<T: JWSAlgorithm> private constructor(
    val header: JOSEHeader<T>,
    private val claimSet: Map<String, JsonElement>
): JWTClaims {
    companion object {
        class JWTClaimSetBuilder internal constructor() {
            private val values: MutableMap<String, JsonPrimitive> = LinkedHashMap(10)

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

            fun issuer(i: String) = claim("iss", i)
            fun subject(s: String) = claim("sub", s)
            fun audience(a: String) = claim("aud", a)
            fun expiresAt(d: LocalDateTime) = claim("exp", d.jwtNumericDate())
            fun notBefore(d: LocalDateTime) = claim("nbf", d.jwtNumericDate())
            fun issuedAt(d: LocalDateTime) = claim("iat", d.jwtNumericDate())
            fun issuedNow() = issuedAt(LocalDateTime.now())
            fun jwtID(id: String) = claim("jti", id)

            fun build(): Map<String, JsonPrimitive> = Collections.unmodifiableMap(values)
        }
        val format = Json
        private val prettyFormat = Json {
            prettyPrint = true
        }

        fun es256(keyID: String? = null, claims: JWTClaimSetBuilder.() -> Unit): JWT<JWSES256Algorithm> = buildJWT(JOSEHeader(JWSES256Algorithm, JOSEType.JWT, keyID), claims)
        fun es256k(keyID: String? = null, claims: JWTClaimSetBuilder.() -> Unit): JWT<JWSES256KAlgorithm> = buildJWT(JOSEHeader(JWSES256KAlgorithm, JOSEType.JWT, keyID), claims)
        fun es384(keyID: String? = null, claims: JWTClaimSetBuilder.() -> Unit): JWT<JWSES384Algorithm> = buildJWT(JOSEHeader(JWSES384Algorithm, JOSEType.JWT, keyID), claims)
        fun es512(keyID: String? = null, claims: JWTClaimSetBuilder.() -> Unit): JWT<JWSES512Algorithm> = buildJWT(JOSEHeader(JWSES512Algorithm, JOSEType.JWT, keyID), claims)

        fun rs256(keyID: String? = null, claims: JWTClaimSetBuilder.() -> Unit): JWT<JWSRSA256Algorithm> = buildJWT(JOSEHeader(JWSRSA256Algorithm, JOSEType.JWT, keyID), claims)
        fun rs384(keyID: String? = null, claims: JWTClaimSetBuilder.() -> Unit): JWT<JWSRSA384Algorithm> = buildJWT(JOSEHeader(JWSRSA384Algorithm, JOSEType.JWT, keyID), claims)
        fun rs512(keyID: String? = null, claims: JWTClaimSetBuilder.() -> Unit): JWT<JWSRSA512Algorithm> = buildJWT(JOSEHeader(JWSRSA512Algorithm, JOSEType.JWT, keyID), claims)

        fun hs256(keyID: String? = null, claims: JWTClaimSetBuilder.() -> Unit): JWT<JWSHMAC256Algorithm> = buildJWT(JOSEHeader(JWSHMAC256Algorithm, JOSEType.JWT, keyID), claims)
        fun hs384(keyID: String? = null, claims: JWTClaimSetBuilder.() -> Unit): JWT<JWSHMAC384Algorithm> = buildJWT(JOSEHeader(JWSHMAC384Algorithm, JOSEType.JWT, keyID), claims)
        fun hs512(keyID: String? = null, claims: JWTClaimSetBuilder.() -> Unit): JWT<JWSHMAC512Algorithm> = buildJWT(JOSEHeader(JWSHMAC512Algorithm, JOSEType.JWT, keyID), claims)

        private fun <T: JWSAlgorithm>buildJWT(header: JOSEHeader<T>, claims: JWTClaimSetBuilder.() -> Unit): JWT<T> {
            val builder = JWTClaimSetBuilder()
            builder.claims()

            return JWT(header, builder.build())
        }

        fun decode(jwt: String): Either<JWTVerificationError, DecodedJWT<out JWSAlgorithm>> {
            val parts = jwt.split(".")
            if (parts.size < 2 || parts.size > 3)
                return JWTVerificationError.InvalidJWT.left()

            val h = format.decodeFromString(JOSEHeader.serializer(PolymorphicSerializer(JWSAlgorithm::class)), jwtDecodeString(parts[0]))
            val claims = format.parseToJsonElement(jwtDecodeString(parts[1]))
            if (claims !is JsonObject)
                return JWTVerificationError.EmptyClaims.left()

            return DecodedJWT(JWT(h, claims.toMap()), parts).right()
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

    override fun keyID(): Option<String> = Option.fromNullable(header.keyID)
    override fun issuer(): Option<String> = claimValue("iss")
    override fun subject(): Option<String> = claimValue("sub")
    override fun audience(): Option<String> = claimValue("aud")
    override fun expiresAt(): Option<LocalDateTime> = claimValueAsLong("exp").map { it.fromJWTNumericDate() }
    override fun notBefore(): Option<LocalDateTime> = claimValueAsLong("nbf").map { it.fromJWTNumericDate() }
    override fun issuedAt(): Option<LocalDateTime> = claimValueAsLong("iat").map { it.fromJWTNumericDate() }
    override fun jwtID(): Option<String> = claimValue("jti")

    fun setKeyID(keyID: String): JWT<T> {
        return JWT(header.copy(keyID = keyID), claimSet)
    }

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
internal fun LocalDateTime.jwtNumericDate(): Long = this.toEpochSecond(ZoneOffset.UTC)
internal fun Long.fromJWTNumericDate(): LocalDateTime = LocalDateTime.ofEpochSecond(this, 0, ZoneOffset.UTC)
internal fun jwtEncodeBytes(data: ByteArray): String = String(Base64.getUrlEncoder().encode(data)).trimEnd('=') // remove trailing '=' as per JWT spec
internal fun jwtDecodeString(data: String): String = String(Base64.getUrlDecoder().decode(data))
internal fun decodeString(data: String): ByteArray = Base64.getUrlDecoder().decode(data)
internal fun stringToBytes(data: String): Either<Throwable, ByteArray> = Either.catch { data.toByteArray(Charsets.UTF_8) }