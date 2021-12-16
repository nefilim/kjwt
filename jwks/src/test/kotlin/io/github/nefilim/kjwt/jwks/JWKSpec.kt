package io.github.nefilim.kjwt.jwks

import arrow.core.left
import arrow.core.right
import io.github.nefilim.kjwt.JWSAlgorithm
import io.github.nefilim.kjwt.JWSES256Algorithm
import io.github.nefilim.kjwt.JWSRSA256Algorithm
import io.github.nefilim.kjwt.JWTKeyID
import io.github.nefilim.kjwt.generateKeyPair
import io.github.nefilim.kjwt.jwks.CachedJWKSProvider.cached
import io.github.nefilim.kjwt.jwks.JWK.Companion.buildKey
import io.github.nefilim.kjwt.jwks.WellKnownJWKSProvider.downloadJWKS
import io.github.nefilim.kjwt.jwks.WellKnownJWKSProvider.getJWKProvider
import io.kotest.assertions.arrow.core.shouldBeLeft
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.core.spec.style.WordSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.kotest.matchers.types.shouldBeTypeOf
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.delay
import kotlinx.serialization.PolymorphicSerializer
import kotlinx.serialization.json.Json
import java.security.PublicKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.util.*
import kotlin.time.ExperimentalTime
import kotlin.time.Duration.Companion.milliseconds

@OptIn(ExperimentalTime::class)
class JWKSSpec: WordSpec() {
    init {
        "JWK" should {
            "deserialize and build keys correctly when valid" {
                val json = Json {
                    isLenient = true
                    ignoreUnknownKeys = true
                }

                with(json.decodeFromString(JWK.serializer(PolymorphicSerializer(JWSAlgorithm::class)), ECJWK)) {
                    algorithm shouldBe (JWSES256Algorithm)
                    shouldBeTypeOf<JWK<JWSES256Algorithm>>() // results in smart cast for the next line
                    buildKey().shouldBeRight()
                    build<RSAPublicKey>().shouldBeLeft(JWKError.AlgorithmKeyMismatch)
                }

                with(json.decodeFromString(JWK.serializer(PolymorphicSerializer(JWSAlgorithm::class)), RSAJWK)) {
                    algorithm shouldBe (JWSRSA256Algorithm)
                    shouldBeTypeOf<JWK<JWSRSA256Algorithm>>() // results in smart cast for the next line
                    buildKey().shouldBeRight()
                    build<ECPublicKey>().shouldBeLeft(JWKError.AlgorithmKeyMismatch)
                }
            }
        }
        "WellKnownJWKS" should {
            "download and parse JWKS" {
                with (WellKnownJWKSProvider.WellKnownContext("https://www.googleapis.com/oauth2/v3/certs").getJWKProvider<RSAPublicKey>(::downloadJWKS)) {
                    this().shouldBeRight()
                    this.getKey(JWTKeyID("c1892eb49d7ef9adf8b2e14c05ca0d032714a237")).shouldBeRight().shouldBeInstanceOf<RSAPublicKey>()
                }
            }
        }
        "CachedJWKS" should {
            "refresh cache" {
                val keyID = JWTKeyID(UUID.randomUUID().toString())
                with (randomJWKS<RSAPublicKey>(keyID).cached(0.milliseconds, GlobalScope)) {
                    var previousKey: RSAPublicKey? = null
                    repeat(10) {
                        this().shouldBeRight()
                        this.getKey(keyID).shouldBeRight().shouldBeInstanceOf<RSAPublicKey>().also {
                            println("got key: $it")
                            it shouldNotBe (previousKey)
                            previousKey = it
                        }
                        delay(350.milliseconds)
                    }
                }
            }
        }
    }
}

inline fun <reified P: PublicKey>randomJWKS(keyID: JWTKeyID): JWKSProvider<P> = JWKSProvider {
    when (P::class) {
        RSAPublicKey::class -> {
            mapOf(keyID to generateKeyPair(JWSRSA256Algorithm).first as P).right()
        }
        ECPublicKey::class -> {
            mapOf(keyID to generateKeyPair(JWSES256Algorithm).first as P).right()
        }
        else ->
            JWKError.AlgorithmKeyMismatch.left()
    }
}

val ECJWK = """
    { 
        "kty":"EC",
        "alg":"ES256",
        "crv":"P-256",
        "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
        "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
        "use":"enc",
        "kid":"1"
    }
""".trimIndent()

val RSAJWK = """
    {
        "alg": "RS256",
        "kty": "RSA",
        "use": "sig",
        "n": "yqjDsay4m-HI1Sx9P2kltQk98TDLfiX-RbdDhLvV_A-Ukj_Y3YwBhraR_WBBAu8U-LIpXwgCd8rypEiYeU3QQGtcUijFDuIA2LmP33WKRG36sSExiaiQA_4Xw-RdvdQuW1Av9PXcVKjLMJvQG-9zYnUUEKpZR49cPh0eBr2sk2Vh_z5end3Xe-5FVGkI1CoIlVeOprUENKDCYq68T7RXEA5GuA4zdRJYv7yt1ore5KundhBg3-TTFTk0HhzaM2qKOKO4Jb56NEsJiPAI5tfSqElpiyst1RDm9AtiwJRTkyJFE0pnLY692KFV0YMopOKJPLcG5eCr2L5Vui9se10eQQ",
        "e": "AQAB",
        "kid": "dawpvKj5y76E2n5XHheeE",
        "x5t": "3ctdK5fkvLgHRIDRnczY3WhRtoQ",
        "x5c": [
            "MIIDDTCCAfWgAwIBAgIJIX+nIZf+r5uAMA0GCSqGSIb3DQEBCwUAMCQxIjAgBgNVBAMTGWRldi0xeGxqcjJhdC51cy5hdXRoMC5jb20wHhcNMjEwOTEzMTUyNzU3WhcNMzUwNTIzMTUyNzU3WjAkMSIwIAYDVQQDExlkZXYtMXhsanIyYXQudXMuYXV0aDAuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyqjDsay4m+HI1Sx9P2kltQk98TDLfiX+RbdDhLvV/A+Ukj/Y3YwBhraR/WBBAu8U+LIpXwgCd8rypEiYeU3QQGtcUijFDuIA2LmP33WKRG36sSExiaiQA/4Xw+RdvdQuW1Av9PXcVKjLMJvQG+9zYnUUEKpZR49cPh0eBr2sk2Vh/z5end3Xe+5FVGkI1CoIlVeOprUENKDCYq68T7RXEA5GuA4zdRJYv7yt1ore5KundhBg3+TTFTk0HhzaM2qKOKO4Jb56NEsJiPAI5tfSqElpiyst1RDm9AtiwJRTkyJFE0pnLY692KFV0YMopOKJPLcG5eCr2L5Vui9se10eQQIDAQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBSkI22sJou33JK1A5ya+aUmhJqNGTAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEBAGxr8smJmu/NcDPVsyeulnaWJZmUZ/8vz1bud/yn9jJCS/5F5E8UvU+o3yqY+vmbmBEVGJvqgAxsYX7/7sulYknI+ZPaVmOgFyLM2UpxwQ7TWoTu0i5Vx5/0f6J7UuGIktOySjJFJoKonDJI90bTxD3fwXzgUAzcaAfVQ/gVbjXkQhV+Xysbtotl3nB/lxHuQ0JtOYHljoXuGgXimPtZLIz+FTnkN7kgbwF9Clr/WJUyd/o1fa8CZYKD8MLiu7VFoNXB7wi4elWVPmnlgFDaxPzfBxmR6BXI1xLeEgJgbb2ZC3+vW9xJmgGzBxPknt3ufU1aqcVwRa7UsTY9iLu47LM="
        ]
    }
""".trimIndent()