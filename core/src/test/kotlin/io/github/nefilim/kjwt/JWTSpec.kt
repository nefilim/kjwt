package io.github.nefilim.kjwt

import arrow.core.ValidatedNel
import io.github.nefilim.kjwt.ClaimsVerification.audience
import io.github.nefilim.kjwt.ClaimsVerification.expired
import io.github.nefilim.kjwt.ClaimsVerification.issuer
import io.github.nefilim.kjwt.ClaimsVerification.notBefore
import io.github.nefilim.kjwt.ClaimsVerification.optionalOptionClaim
import io.github.nefilim.kjwt.ClaimsVerification.requiredOptionClaim
import io.github.nefilim.kjwt.ClaimsVerification.subject
import io.github.nefilim.kjwt.ClaimsVerification.validateClaims
import io.github.nefilim.kjwt.JWT.Companion.es256
import io.github.nefilim.kjwt.JWT.Companion.es256k
import io.github.nefilim.kjwt.JWT.Companion.es384
import io.github.nefilim.kjwt.JWT.Companion.es512
import io.github.nefilim.kjwt.JWT.Companion.hs256
import io.github.nefilim.kjwt.JWT.Companion.hs384
import io.github.nefilim.kjwt.JWT.Companion.hs512
import io.github.nefilim.kjwt.JWT.Companion.rs256
import io.github.nefilim.kjwt.JWT.Companion.rs384
import io.github.nefilim.kjwt.JWT.Companion.rs512
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.crypto.MACVerifier
import com.nimbusds.jose.crypto.RSASSAVerifier
import io.kotest.assertions.arrow.core.shouldBeInvalid
import io.kotest.assertions.arrow.core.shouldBeLeft
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.assertions.arrow.core.shouldBeSome
import io.kotest.assertions.arrow.core.shouldBeValid
import io.kotest.core.spec.style.WordSpec
import io.kotest.matchers.shouldBe
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.ECGenParameterSpec
import java.time.Instant
import java.time.LocalDateTime
import java.time.ZoneId
import com.nimbusds.jwt.SignedJWT as NimbusSignedJWT

class JWTSpec: WordSpec() {
    init {
        "JWT" should {
            "build JWT claim set" {
                with(es256("123") {
                    subject("1234567890")
                    issuer("nefilim")
                    claim("name", "John Doe")
                    claim("admin", true)
                    issuedAt(LocalDateTime.ofInstant(Instant.ofEpochSecond(1516239022), ZoneId.of("UTC")))
                }) {
                    keyID().shouldBeSome() shouldBe "123"
                    issuer().shouldBeSome() shouldBe "nefilim"
                    subject().shouldBeSome() shouldBe "1234567890"
                    claimValue("name").shouldBeSome() shouldBe "John Doe"
                    claimValueAsBoolean("admin").shouldBeSome() shouldBe true
                    issuedAt().shouldBeSome() shouldBe LocalDateTime.ofInstant(Instant.ofEpochSecond(1516239022), ZoneId.of("UTC"))
                }
            }

            "encode header & claims set" {
                val jwt = es256(null) {
                    subject("1234567890")
                    claim("name", "John Doe")
                    claim("admin", true)
                    issuedAt(LocalDateTime.ofInstant(Instant.ofEpochSecond(1516239022), ZoneId.of("UTC")))
                }

                jwt.encode() shouldBe "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0"

                val jwtWithKeyID = es256("123") {
                    subject("1234567890")
                    claim("name", "John Doe")
                    claim("admin", true)
                    issuedAt(LocalDateTime.ofInstant(Instant.ofEpochSecond(1516239022), ZoneId.of("UTC")))
                }

                jwtWithKeyID.encode() shouldBe "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEyMyJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0"
            }

            "decode" {
                val rawJWT = es256 {
                    subject("1234567890")
                    claim("name", "John Doe")
                    claim("admin", true)
                    issuedAt(LocalDateTime.ofInstant(Instant.ofEpochSecond(1516239022), ZoneId.of("UTC")))
                }

                JWT.decode(rawJWT.encode()).shouldBeRight().also {
                    it.parts.size shouldBe 2
                    it.jwt shouldBe rawJWT
                }

                val (_, privateKey) = generateECKeyPair(JWSES256Algorithm)
                val signedJWT = rawJWT.sign(privateKey).shouldBeRight()
                JWT.decode(signedJWT.rendered).shouldBeRight().also {
                    it.parts.size shouldBe 3
                    it.jwt shouldBe rawJWT
                }
            }

            "sign & verify supported elliptical signatures" {
                listOf(
                    ::es256,
                    ::es256k,
                    ::es384,
                    ::es512,
                ).forEach { createJWT ->
                    val rawJWT = createJWT("123") {
                        subject("1234567890")
                        issuer("nefilim")
                        claim("name", "John Doe")
                        claim("admin", true)
                        issuedAt(LocalDateTime.ofInstant(Instant.ofEpochSecond(1516239022), ZoneId.of("UTC")))
                    }

                    val (publicKey, privateKey) = generateECKeyPair(rawJWT.header.algorithm)

                    val signedJWT = rawJWT.sign(privateKey)
                    signedJWT.shouldBeRight().also {
                        println(it.rendered)
                        NimbusSignedJWT.parse(it.rendered).verify(ECDSAVerifier(publicKey)) shouldBe true
                        verifySignature<JWSECDSAAlgorithm>(it.rendered, publicKey).shouldBeRight() shouldBe it.jwt
                    }
                }
            }

            "sign & verify supported RSA signatures" {
                listOf(
                    ::rs256,
                    ::rs384,
                    ::rs512,
                ).forEach { createJWT ->
                    val rawJWT = createJWT(null) {
                        subject("1234567890")
                        claim("name", "John Doe")
                        claim("admin", true)
                        issuedAt(LocalDateTime.ofInstant(Instant.ofEpochSecond(1516239022), ZoneId.of("UTC")))
                    }

                    val (publicKey, privateKey) = generateRSAKeyPair()

                    val signedJWT = rawJWT.sign(privateKey)
                    signedJWT.shouldBeRight().also {
                        NimbusSignedJWT.parse(it.rendered).verify(RSASSAVerifier(publicKey)) shouldBe true
                        verifySignature<JWSRSAAlgorithm>(it.rendered, publicKey).shouldBeRight() shouldBe it.jwt
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
                        issuedAt(LocalDateTime.ofInstant(Instant.ofEpochSecond(1516239022), ZoneId.of("UTC")))
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
                val (_, privateKey) = generateECKeyPair(JWSES256Algorithm)
                val (badPublicKey, badPrivateKey) = generateRSAKeyPair()

                val jwt = es256() {
                    subject("1234567890")
                    claim("name", "John Doe")
                    claim("admin", true)
                    issuedAt(LocalDateTime.ofInstant(Instant.ofEpochSecond(1516239022), ZoneId.of("UTC")))
                }

                // below stanza should NOT compile, type system should prevent you from signing a JWT with the wrong kind of key
                // jwt.sign(badPrivateKey, JWSRSA256Algorithm)  
                // jwt.sign(badPrivateKey, JWSES256Algorithm)

                jwt.sign(privateKey).shouldBeRight().also {
                    verifySignature<JWSRSAAlgorithm>(it.rendered, badPublicKey).shouldBeLeft() shouldBe JWTVerificationError.AlgorithmMismatch
                }
            }

            "support standard validations" {
                val jwt = es256() {
                    subject("1234567890")
                    issuer("thecompany")
                    audience("http://thecompany.com")
                    claim("name", "John Doe")
                    claim("admin", true)
                    expiresAt(LocalDateTime.now().plusHours(1))
                    notBefore(LocalDateTime.now().minusMinutes(1))
                    issuedNow()
                }

                fun standardValidation(claims: JWTClaims): ValidatedNel<out JWTVerificationError, JWTClaims> =
                    validateClaims(notBefore, expired, issuer("thecompany"), subject("1234567890"), audience("http://thecompany.com"))(claims)

                standardValidation(jwt).shouldBeValid()

                val invalidJWT = es256() {
                    subject("123456789")
                    issuer("theothercompany")
                    audience("http://phish.com")
                    claim("name", "John Doe")
                    claim("admin", true)
                    expiresAt(LocalDateTime.now().minusHours(1))
                    notBefore(LocalDateTime.now().plusMinutes(1))
                    issuedAt(LocalDateTime.now())
                }

                standardValidation(invalidJWT).shouldBeInvalid().toSet()
                    .shouldBe(
                        setOf(
                            JWTValidationError.TokenExpired,
                            JWTValidationError.TokenNotValidYet,
                            JWTValidationError.InvalidIssuer,
                            JWTValidationError.InvalidAudience,
                            JWTValidationError.InvalidSubject
                        )
                    )
            }

            "support custom validations for required/optional claims" {
                val jwt = es256() {
                    subject("1234567890")
                    issuer("theco")
                    claim("name", "John Doe")
                    claim("admin", true)
                    notBefore(LocalDateTime.now().plusMinutes(1))
                    issuedAt(LocalDateTime.ofInstant(Instant.ofEpochSecond(1516239022), ZoneId.of("UTC")))
                }

                validateClaims(requiredOptionClaim("admin", { claimValueAsBoolean("admin") }) { it })(jwt).shouldBeValid()

                validateClaims(requiredOptionClaim("alsoadmin", { claimValueAsBoolean("alsoadmin") }) { it })(jwt)
                    .shouldBeInvalid().toSet() shouldBe setOf(JWTValidationError.RequiredClaimIsMissing("alsoadmin"))

                validateClaims(optionalOptionClaim("alsoadmin", { claimValueAsBoolean("alsoadmin") }) { it })(jwt)
                    .shouldBeValid()
            }

            "put the receive side all together" {
                val (publicKey, privateKey) = generateECKeyPair(JWSES256Algorithm)

                val jwt = es256("123") {
                    subject("1234567890")
                    issuer("thecompany")
                    audience("http://thecompany.com")
                    claim("name", "John Doe")
                    claim("admin", true)
                    expiresAt(LocalDateTime.now().plusHours(1))
                    notBefore(LocalDateTime.now().minusMinutes(1))
                    issuedNow()
                }

                val standardValidation: ClaimsValidator = { claims ->
                    validateClaims(notBefore, expired, issuer("thecompany"), subject("1234567890"), audience("http://thecompany.com"))(claims)
                }
                val signedJWT = jwt.sign(privateKey).shouldBeRight()
                verify<JWSES256Algorithm>(signedJWT.rendered, publicKey, standardValidation).shouldBeValid()

                val (badPublicKey, _) = generateECKeyPair(JWSES256Algorithm)
                verify<JWSES256Algorithm>(signedJWT.rendered, badPublicKey, standardValidation).shouldBeInvalid().toSet()
                    .shouldBe(setOf(JWTVerificationError.InvalidSignature))

                val validator = validateClaims(standardValidation, requiredOptionClaim("admin", { claimValueAsBoolean("admin") }, { !it }))
                verify<JWSES256Algorithm>(signedJWT.rendered, publicKey, validator).shouldBeInvalid().toSet()
                    .shouldBe(setOf(JWTValidationError.RequiredClaimIsInvalid("admin")))
            }
        }
    }
}

fun generateECKeyPair(algorithm: JWSECDSAAlgorithm): Pair<ECPublicKey, ECPrivateKey> {
    val ecSpec = ECGenParameterSpec(algorithm.curve)
    val g = KeyPairGenerator.getInstance("EC")
    g.initialize(ecSpec, SecureRandom())
    val keypair: KeyPair = g.generateKeyPair()
    return keypair.public as ECPublicKey to keypair.private as ECPrivateKey
}

fun generateRSAKeyPair(): Pair<RSAPublicKey, RSAPrivateKey> {
    val generator = KeyPairGenerator.getInstance("RSA")
    generator.initialize(2048)
    val kp = generator.genKeyPair()
    return kp.public as RSAPublicKey to kp.private as RSAPrivateKey
}
