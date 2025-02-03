package io.github.nefilim.kjwt

import arrow.core.EitherNel
import arrow.core.getOrElse
import arrow.core.some
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.crypto.MACVerifier
import com.nimbusds.jose.crypto.RSASSAVerifier
import io.github.nefilim.kjwt.ClaimsVerification.audience
import io.github.nefilim.kjwt.ClaimsVerification.expired
import io.github.nefilim.kjwt.ClaimsVerification.issuer
import io.github.nefilim.kjwt.ClaimsVerification.notBefore
import io.github.nefilim.kjwt.ClaimsVerification.optionalOptionClaim
import io.github.nefilim.kjwt.ClaimsVerification.requiredOptionClaim
import io.github.nefilim.kjwt.ClaimsVerification.subject
import io.github.nefilim.kjwt.ClaimsVerification.validateClaims
import io.github.nefilim.kjwt.JWT.Companion.es256
import io.github.nefilim.kjwt.JWT.Companion.es256WithoutTypeHeader
import io.github.nefilim.kjwt.JWT.Companion.es256k
import io.github.nefilim.kjwt.JWT.Companion.es384
import io.github.nefilim.kjwt.JWT.Companion.es512
import io.github.nefilim.kjwt.JWT.Companion.hs256
import io.github.nefilim.kjwt.JWT.Companion.hs384
import io.github.nefilim.kjwt.JWT.Companion.hs512
import io.github.nefilim.kjwt.JWT.Companion.rs256
import io.github.nefilim.kjwt.JWT.Companion.rs384
import io.github.nefilim.kjwt.JWT.Companion.rs512
import io.kotest.assertions.arrow.core.shouldBeLeft
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.assertions.arrow.core.shouldBeSome
import io.kotest.core.spec.style.WordSpec
import io.kotest.matchers.shouldBe
import mu.KotlinLogging
import java.time.Clock
import java.time.Instant
import java.time.temporal.ChronoUnit
import com.nimbusds.jwt.SignedJWT as NimbusSignedJWT

class JWTSpec: WordSpec() {
    private val logger = KotlinLogging.logger { }

    init {
        "JWT" should {
            "build JWT claim set" {
                with(es256(JWTKeyID("123")) {
                    subject("1234567890")
                    issuer("nefilim")
                    claim("name", "John Doe")
                    claim("admin", true)
                    issuedAt(Instant.ofEpochSecond(1516239022))
                }) {
                    keyID().shouldBeSome().id shouldBe "123"
                    issuer().shouldBeSome() shouldBe "nefilim"
                    subject().shouldBeSome() shouldBe "1234567890"
                    claimValue("name").shouldBeSome() shouldBe "John Doe"
                    claimValueAsBoolean("admin").shouldBeSome() shouldBe true
                    issuedAt().shouldBeSome() shouldBe Instant.ofEpochSecond(1516239022)
                }
            }

            "encode header & claims set" {
                val jwt = es256(null) {
                    subject("1234567890")
                    claim("name", "John Doe")
                    claim("admin", true)
                    issuedAt(Instant.ofEpochSecond(1516239022))
                }

                jwt.encode() shouldBe "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0"

                val jwtWithKeyID = es256(JWTKeyID("123")) {
                    subject("1234567890")
                    claim("name", "John Doe")
                    claim("admin", true)
                    issuedAt(Instant.ofEpochSecond(1516239022))
                }

                jwtWithKeyID.encode() shouldBe "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEyMyJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0"
            }

            "decode and decodeT" {
                val rawJWT = es256 {
                    subject("1234567890")
                    claim("name", "John Doe")
                    claim("admin", true)
                    issuedAt(Instant.ofEpochSecond(1516239022))
                }

                JWT.decode(rawJWT.encode()).shouldBeRight().also {
                    it.parts.size shouldBe 2
                    it.jwt shouldBe rawJWT
                }

                val (_, privateKey) = generateKeyPair(JWSES256Algorithm)
                val signedJWT = rawJWT.sign(privateKey).shouldBeRight()
                JWT.decode(signedJWT.rendered).shouldBeRight().also {
                    it.parts.size shouldBe 3
                    it.jwt shouldBe rawJWT
                }

                JWT.decodeT(signedJWT.rendered, JWSES256Algorithm).shouldBeRight().also {
                    it.parts.size shouldBe 3
                    it.jwt shouldBe rawJWT
                }

                JWT.decodeT(signedJWT.rendered, JWSRSA256Algorithm).shouldBeLeft(KJWTVerificationError.AlgorithmMismatch)
            }

            "decode spec violating types" {
                val rawJWT = es256 {
                    subject("1234567890")
                    issuedAt(Instant.ofEpochSecond(1516239022))
                }
                // create a token with a spec violating lowercase type of "jwt"
                val jwtString = listOf(
                    """
                        {
                            "alg": "${rawJWT.header.algorithm.headerID}",
                            "typ": "jwt" 
                        }
                    """.trimIndent(),
                    """
                        {
                            "sub": "${rawJWT.subject().getOrElse { "" }}",
                            "iat": ${rawJWT.issuedAt().map { it.epochSecond }.getOrElse { 0 }}
                        }
                    """.trimIndent()
                ).joinToString(".") {
                    jwtEncodeBytes(it.toByteArray(Charsets.UTF_8))
                }
                JWT.decode(jwtString).shouldBeRight().also {
                    it.parts.size shouldBe 2
                    it.jwt shouldBe rawJWT
                }
            }

            "decode JWT with missing type header" {
                val rawJWT = es256WithoutTypeHeader {
                    subject("1234567890")
                    issuedAt(Instant.ofEpochSecond(1516239022))
                }
                // create a token with a spec violating lowercase type of "jwt"
                val jwtString = listOf(
                    """
                        {
                            "alg": "${rawJWT.header.algorithm.headerID}"
                        }
                    """.trimIndent(),
                    """
                        {
                            "sub": "${rawJWT.subject().getOrElse { "" }}",
                            "iat": ${rawJWT.issuedAt().map { it.epochSecond }.getOrElse { 0 }}
                        }
                    """.trimIndent()
                ).joinToString(".") {
                    jwtEncodeBytes(it.toByteArray(Charsets.UTF_8))
                }
                JWT.decode(jwtString).shouldBeRight().also {
                    it.parts.size shouldBe 2
                    it.jwt shouldBe rawJWT
                }
            }

            "support arbitrary JSON claim values" {
                val thelist = listOf("tagA", "tagB", "tagC")
                val rawJWT = es256 {
                    subject("1234567890")
                    claim("name", "John Doe")
                    claim("admin", true)
                    claim("thenumber", 42)
                    claim("thelist", thelist)
                    issuedAt(Instant.ofEpochSecond(1516239022))
                }

                JWT.decode(rawJWT.encode()).shouldBeRight().also {
                    it.parts.size shouldBe 2
                    it.jwt shouldBe rawJWT
                    it.claimValueAsList("thelist") shouldBe thelist
                    it.claimValueAsBoolean("admin").shouldBeSome() shouldBe true
                    it.claimValueAsInt("thenumber").shouldBeSome() shouldBe 42
                }
            }

            "sign & verify supported elliptical signatures" {
                listOf(
                    ::es256 to JWSES256Algorithm,
                    ::es256k to JWSES256KAlgorithm,
                    ::es384 to JWSES384Algorithm,
                    ::es512 to JWSES512Algorithm,
                ).forEach { pair ->
                    val createJWT = pair.first
                    val rawJWT = createJWT(JWTKeyID("123")) {
                        subject("1234567890")
                        issuer("nefilim")
                        claim("name", "John Doe")
                        claim("admin", true)
                        issuedAt(Instant.ofEpochSecond(1516239022))
                    }

                    val (publicKey, privateKey) = generateKeyPair(rawJWT.header.algorithm)

                    val signedJWT = rawJWT.sign(privateKey)
                    signedJWT.shouldBeRight().also {
                        logger.info { it.rendered }
                        NimbusSignedJWT.parse(it.rendered).verify(ECDSAVerifier(publicKey)) shouldBe true
                        verifySignature(it.rendered, publicKey, pair.second).shouldBeRight() shouldBe it.jwt
                    }
                }
            }

            "sign & verify supported RSA signatures" {
                listOf(
                    ::rs256 to JWSRSA256Algorithm,
                    ::rs384 to JWSRSA384Algorithm,
                    ::rs512 to JWSRSA512Algorithm,
                ).forEach { pair ->
                    val rawJWT = pair.first(null) {
                        subject("1234567890")
                        claim("name", "John Doe")
                        claim("admin", true)
                        issuedAt(Instant.ofEpochSecond(1516239022))
                    }

                    val (publicKey, privateKey) = generateKeyPair(rawJWT.header.algorithm)

                    val signedJWT = rawJWT.sign(privateKey)
                    signedJWT.shouldBeRight().also {
                        NimbusSignedJWT.parse(it.rendered).verify(RSASSAVerifier(publicKey)) shouldBe true
                        verifySignature(it.rendered, publicKey, pair.second).shouldBeRight() shouldBe it.jwt
                    }
                }
            }

            "sign & verify supported HMAC signatures" {
                listOf(
                    ::hs256,
                    ::hs384,
                    ::hs512,
                ).forEach { createJWT ->
                    val rawJWT = createJWT(null) {
                        subject("1234567890")
                        claim("name", "John Doe")
                        claim("admin", true)
                        issuedAt(Instant.ofEpochSecond(1516239022))
                    }

                    val secret = "iwFPzTFi41xBhlvqjYPiX4NKRFqAubl5zHAjeuK9s0MjvcCOgj84RgxRU2u8k7dUY1czPSCs4wAlePkLFTnsRpcaJdf07MJzloG63W1Mcfg9CCW9WOD80aOmkRnuYll5w8CYFj2qMP5D69XaGcjsu0rw6cjgkBhDDltSg5VZtDPYkGVuYw5NSUqk90PtKT9ZmF88bI2gadjhl3GS5ZBfOEisgNHnguQNfPFT3TDq8c5pLHoyAsErbNYaiwOjRfe2"

                    val signedJWT = rawJWT.sign(secret)
                    signedJWT.shouldBeRight().also {
                        NimbusSignedJWT.parse(it.rendered).verify(MACVerifier(secret)) shouldBe true
                        verifySignature<JWSHMACAlgorithm>(it.rendered, secret).shouldBeRight() shouldBe it.jwt
                    }
                }
            }

            "fail for mismatched algorithm & key" {
                es256() {
                    subject("1234567890")
                    claim("name", "John Doe")
                    claim("admin", true)
                    issuedAt(Instant.ofEpochSecond(1516239022))
                }

                // below stanzas should NOT compile, type system should prevent you from signing a JWT with the wrong kind of key
                // val (badPublicKey, badPrivateKey) = generateKeyPair(JWSRSA256Algorithm)
                // jwt.sign(badPrivateKey, JWSRSA256Algorithm)
                // jwt.sign(badPrivateKey, JWSES256Algorithm)
                // jwt.sign(privateKey).shouldBeRight().also {
                //    verifySignature<JWSRSAAlgorithm>(it.rendered, badPublicKey).shouldBeLeft() shouldBe KJWTVerificationError.AlgorithmMismatch
                // }
            }

            "support standard validations" {
                val jwt = es256 {
                    subject("1234567890")
                    issuer("thecompany")
                    audience("http://thecompany.com")
                    claim("name", "John Doe")
                    claim("admin", true)
                    expiresAt(Instant.now().plus(1, ChronoUnit.HOURS))
                    notBefore(Instant.now().minus(1, ChronoUnit.MINUTES))
                    issuedNow()
                }

                fun standardValidation(claims: JWTClaims): EitherNel<KJWTVerificationError, JWTClaims> =
                    validateClaims(notBefore(), expired(), issuer("thecompany"), subject("1234567890"), audience("http://thecompany.com"))(claims)

                standardValidation(jwt).shouldBeRight()

                val invalidJWT = es256 {
                    subject("123456789")
                    issuer("theothercompany")
                    audience("http://phish.com")
                    claim("name", "John Doe")
                    claim("admin", true)
                    expiresAt(Instant.now().minus(1, ChronoUnit.MINUTES))
                    notBefore(Instant.now().plus(1, ChronoUnit.MINUTES))
                    issuedAt(Instant.now())
                }

                standardValidation(invalidJWT).shouldBeLeft().toSet().shouldBe(
                        setOf(
                            KJWTValidationError.TokenExpired,
                            KJWTValidationError.TokenNotValidYet,
                            KJWTValidationError.InvalidIssuer,
                            KJWTValidationError.InvalidAudience,
                            KJWTValidationError.InvalidSubject
                        )
                    )
            }

            "cross timezone issues and validation" {
                fun standardValidation(claims: JWTClaims): EitherNel<out KJWTVerificationError, JWTClaims> =
                    validateClaims(notBefore(), expired())(claims)

                val utcClock = Clock.systemUTC()
                val defaultClock = Clock.systemDefaultZone()

                val invalidJWT = es256 {
                    subject("123456789")
                    issuer("theothercompany")
                    audience("http://phish.com")
                    claim("name", "John Doe")
                    claim("admin", true)
                    expiresAt(defaultClock.instant().plus(1, ChronoUnit.MINUTES))
                    notBefore(utcClock.instant().minus(1, ChronoUnit.SECONDS))
                    issuedNow()
                }

                standardValidation(invalidJWT).shouldBeRight()
            }

            "support custom validations for required/optional claims" {
                val jwt = es256() {
                    subject("1234567890")
                    issuer("theco")
                    claim("name", "John Doe")
                    claim("admin", true)
                    notBefore(Instant.now().plus(1, ChronoUnit.MINUTES))
                    issuedAt(Instant.ofEpochSecond(1516239022))
                }

                validateClaims(
                    requiredOptionClaim(
                        "admin",
                        { claimValueAsBoolean("admin") }) { it })(jwt).shouldBeRight()

                validateClaims(requiredOptionClaim("alsoadmin", { claimValueAsBoolean("alsoadmin") }) { it })(jwt)
                    .shouldBeLeft().toSet() shouldBe setOf(KJWTValidationError.RequiredClaimIsMissing("alsoadmin"))

                validateClaims(optionalOptionClaim("alsoadmin", { claimValueAsBoolean("alsoadmin") }) { it })(jwt)
                    .shouldBeRight()
            }

            "put the receive side all together" {
                val (publicKey, privateKey) = generateKeyPair(JWSES256Algorithm)

                val jwt = es256(JWTKeyID("123")) {
                    subject("1234567890")
                    issuer("thecompany")
                    audience("http://thecompany.com")
                    claim("name", "John Doe")
                    claim("admin", true)
                    expiresAt(Instant.now().plus(1, ChronoUnit.HOURS))
                    notBefore(Instant.now().minus(1, ChronoUnit.MINUTES))
                    issuedNow()
                }

                val standardValidation: ClaimsValidator = { claims ->
                    validateClaims(notBefore(), expired(), issuer("thecompany"), subject("1234567890"), audience("http://thecompany.com"))(claims)
                }
                val signedJWT = jwt.sign(privateKey).shouldBeRight()
                verify(
                    signedJWT.rendered,
                    ECPublicKeyProvider { publicKey.some() },
                    standardValidation,
                    JWSES256Algorithm
                ).shouldBeRight()

                // should not even compile!
                //val (badPublicKey, _) = generateKeyPair(JWSES256Algorithm)
                //verify<JWSES256Algorithm>(signedJWT.rendered, badPublicKey, standardValidation).shouldBeLeft().toSet()
                //    .shouldBe(setOf(KJWTVerificationError.InvalidSignature))

                val validator = validateClaims(standardValidation, requiredOptionClaim("admin", { claimValueAsBoolean("admin") }, { !it }))
                verify(signedJWT.rendered, ECPublicKeyProvider { publicKey.some() }, validator, JWSES256Algorithm)
                    .shouldBeLeft().toSet() shouldBe setOf(KJWTValidationError.RequiredClaimIsInvalid("admin"))
            }

            "overload reified algorithm for verification" {
                val (publicKey, privateKey) = generateKeyPair(JWSES256Algorithm)

                val jwt = es256(JWTKeyID("123")) {
                    subject("1234567890")
                    issuer("thecompany")
                    audience("http://thecompany.com")
                    claim("name", "John Doe")
                    claim("admin", true)
                    expiresAt(Instant.now().plus(1, ChronoUnit.HOURS))
                    notBefore(Instant.now().minus(1, ChronoUnit.MINUTES))
                    issuedNow()
                }

                val standardValidation: ClaimsValidator = { claims ->
                    validateClaims(notBefore(), expired(), issuer("thecompany"), subject("1234567890"), audience("http://thecompany.com"))(claims)
                }
                val signedJWT = jwt.sign(privateKey).shouldBeRight()
                verify(
                    signedJWT.rendered,
                    ECPublicKeyProvider { publicKey.some() },
                    standardValidation,
                    JWSES256Algorithm
                ).shouldBeRight()

                verify(signedJWT.rendered, ECPublicKeyProvider { publicKey.some() }, standardValidation, JWSES512Algorithm)
                    .shouldBeLeft().toSet() shouldBe setOf(KJWTVerificationError.AlgorithmMismatch)
            }
        }
    }
}