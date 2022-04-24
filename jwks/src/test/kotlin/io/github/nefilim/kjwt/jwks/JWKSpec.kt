package io.github.nefilim.kjwt.jwks

import arrow.core.Either
import arrow.core.flatMap
import arrow.core.getOrElse
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
import io.kotest.assertions.fail
import io.kotest.core.spec.style.WordSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.kotest.matchers.types.shouldBeTypeOf
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.delay
import kotlinx.serialization.PolymorphicSerializer
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import mu.KotlinLogging
import java.net.URL
import java.net.URLConnection
import java.security.PublicKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.util.*
import kotlin.time.ExperimentalTime
import kotlin.time.Duration.Companion.milliseconds

@OptIn(ExperimentalTime::class)
class JWKSSpec: WordSpec() {
    private val logger = KotlinLogging.logger { }

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
                    build<RSAPublicKey>().shouldBeLeft().shouldBeInstanceOf<JWKError.AlgorithmKeyMismatch>()
                }

                with(json.decodeFromString(JWK.serializer(PolymorphicSerializer(JWSAlgorithm::class)), RSAJWK)) {
                    algorithm shouldBe (JWSRSA256Algorithm)
                    shouldBeTypeOf<JWK<JWSRSA256Algorithm>>() // results in smart cast for the next line
                    buildKey().shouldBeRight()
                    build<ECPublicKey>().shouldBeLeft().shouldBeInstanceOf<JWKError.AlgorithmKeyMismatch>()
                }
            }
        }
        "WellKnownJWKS" should {
            "download and parse JWKS" {
                val wellKnownContext = WellKnownJWKSProvider.WellKnownContext("https://www.googleapis.com/oauth2/v3/certs")
                downloadJWKS(wellKnownContext).flatMap {
                    Either.fromNullable(Json.parseToJsonElement(it).jsonObject["keys"]?.jsonArray?.first()?.jsonObject?.get("kid")).mapLeft { JWKError.NoSuchKey(JWTKeyID("missing kid?")) }
                }.fold({
                    fail("failed to download JWKS json from Google: $it")
                }, {
                    val kid = JWTKeyID(it.jsonPrimitive.content)
                    logger.info { "downloading JWK for $kid from Google" }
                    with(wellKnownContext.getJWKProvider<RSAPublicKey>(::downloadJWKS)) {
                        this().shouldBeRight()
                        this.getKey(kid).shouldBeRight().shouldBeInstanceOf<RSAPublicKey>()
                    }
                })
            }
            "gracefully handle unsupported algorithms" {
                val jwks = WellKnownJWKSProvider.json.decodeFromString(JWKS.serializer(), UnsupportedAlgorithmInJWK)
                jwks.keys.size shouldBe 2
            }
        }
        "CachedJWKS" should {
            "refresh cache" {
                val keyID = JWTKeyID(UUID.randomUUID().toString())
                with (randomJWKS<RSAPublicKey>(keyID).cached(0.milliseconds, GlobalScope)) {
                    var previousKey: RSAPublicKey? = null
                    repeat(3) {
                        this().shouldBeRight()
                        this.getKey(keyID).shouldBeRight().shouldBeInstanceOf<RSAPublicKey>().also {
                            logger.debug { "got key: $it" }
                            it shouldNotBe (previousKey)
                            previousKey = it
                        }
                        delay(750.milliseconds)
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
            JWKError.AlgorithmKeyMismatch(keyID).left()
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


val UnsupportedAlgorithmInJWK = """
{
"keys": [
{
"kid": "5NVqLy00rEUpMYV7evCXdQuIZ4zEgId-5LfM470iBpU",
"kty": "RSA",
"alg": "RSA-OAEP",
"use": "enc",
"n": "gYRpL9-iFMgo2yb7kS0T9h3kxfeeWYfpHgeKgo2BBgvE6cQ2lJ9ltb0YJg9f6cGLLhyZTyiM_eDMVWwiOLKUS6wAG4pYozNdUXGRovdfEjXz6EhCteIk0AImth1SoNsv5Vb_HwAkMj32lKBnByb-SSAbgVGSZ2MnZHIqOZUU4MLmlFBkhC6CmeDtXnfUlUkrixf8T-EepizJphOCQWcfrzSoQQDRlZqvBYlIHIUHKPcoliolrL5xowYBRaymTjUs0-G8iaEJYzLt0cGdkt4Ni3Zb3F6EvvieiCFJUVVg-bDe_0Lj78YQFb2CqGqIFijdfDSeZgqxYbiq4Nh7lcB32Q",
"e": "AQAB",
"x5c": [
"MIICrzCCAZcCBgGAPpFxtDANBgkqhkiG9w0BAQsFADAbMRkwFwYDVQQDDBBmaWd1cmUtZW1wbG95ZWVzMB4XDTIyMDQxODIxMjQyMFoXDTMyMDQxODIxMjYwMFowGzEZMBcGA1UEAwwQZmlndXJlLWVtcGxveWVlczCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAIGEaS/fohTIKNsm+5EtE/Yd5MX3nlmH6R4HioKNgQYLxOnENpSfZbW9GCYPX+nBiy4cmU8ojP3gzFVsIjiylEusABuKWKMzXVFxkaL3XxI18+hIQrXiJNACJrYdUqDbL+VW/x8AJDI99pSgZwcm/kkgG4FRkmdjJ2RyKjmVFODC5pRQZIQugpng7V531JVJK4sX/E/hHqYsyaYTgkFnH680qEEA0ZWarwWJSByFByj3KJYqJay+caMGAUWspk41LNPhvImhCWMy7dHBnZLeDYt2W9xehL74noghSVFVYPmw3v9C4+/GEBW9gqhqiBYo3Xw0nmYKsWG4quDYe5XAd9kCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEARNqHxasLdYHlwd8IEWYQ4C+HLZKs/RhznVPh75B++1gVcnJHvbvR5op2OlKivqWPIqd2hqxUn5EqTyd1iBfpdV+Ksfk7t8gCkgR+njtrKH+2zjv0ogVVXsya2j/xS+NZYf11/ozZv4DTYrd/IOwHU1wK9trTWZ1BpiBlmS1/38xxQs1g4j0CxYIj9DR7Y53kX+WlXZ8ajsm3k27f0Rad2utYwdPMc3FVjIp23H8URJBB+VH3Ikdk0uNWGPvst88UVu4KqlJilodyhSxRNtT3GuwLkwjFA275fN4J2W+H9C31L8JqgbyLtIqMXIS91fnspMFbav+FZII0oNA0wWVQjg=="
],
"x5t": "Rph0qHDDb9K5EJE-GFPKheTa_88",
"x5t#S256": "1RgKt1HZm5sM82NxqTb8Kv4OOflELieeLcWNZLf8msg"
},
{
"kid": "xY5PjYZLe0YrI2T8_3-SouOTHC3TQjDHKLw15VQAL7M",
"kty": "RSA",
"alg": "RS256",
"use": "sig",
"n": "jr0Yu-Mwe8tuVP12KDydtsd2MfHT_dkCVhuaFZx_u7798IXGT9f_SUtzV4fmy2g5HIKqKrZ5C7aCAe6MzTwWBmmY2gzh2f4Yp3alMavyzVLBIoTnYC_Vx_NgAyYH3cZqt2O5hUz3MonKV8YQ1FpLgzvDIEA04tWi3dn3Ku3pr-ZHRwaRYZ9JGDJnj5fVM9Db8pjMpxLEb1YD0JSb8OGu4WwePHs2K_9vXJ9z3UKe1SFjMBhhvOnRxtawhm7DgS8CpPJBEhzlNE-VY4d0CasD42QUBXJJpS-r7VZjBBUD0oYYs_fsGyuIUOPvxRYLm8QODLSkIxP7R_KZ8k7djY4OBw",
"e": "AQAB",
"x5c": [
"MIICrzCCAZcCBgGAPpFxFzANBgkqhkiG9w0BAQsFADAbMRkwFwYDVQQDDBBmaWd1cmUtZW1wbG95ZWVzMB4XDTIyMDQxODIxMjQyMFoXDTMyMDQxODIxMjYwMFowGzEZMBcGA1UEAwwQZmlndXJlLWVtcGxveWVlczCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAI69GLvjMHvLblT9dig8nbbHdjHx0/3ZAlYbmhWcf7u+/fCFxk/X/0lLc1eH5stoORyCqiq2eQu2ggHujM08FgZpmNoM4dn+GKd2pTGr8s1SwSKE52Av1cfzYAMmB93GardjuYVM9zKJylfGENRaS4M7wyBANOLVot3Z9yrt6a/mR0cGkWGfSRgyZ4+X1TPQ2/KYzKcSxG9WA9CUm/DhruFsHjx7Niv/b1yfc91CntUhYzAYYbzp0cbWsIZuw4EvAqTyQRIc5TRPlWOHdAmrA+NkFAVySaUvq+1WYwQVA9KGGLP37BsriFDj78UWC5vEDgy0pCMT+0fymfJO3Y2ODgcCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAeyrjsrt7Wudt0nCV0FQj/+7qrosuhKLMNmxjU87bXu9TgD1FtZNWxO9fGvraoR1wqqD8mH+hJL6ZF8nsq1Z3+fg2h1ckRkBX7zfF4v6B7h0EXfE2LPw9FoH39D75xPEdqlaA10URO/ExJxBUrv8nWuksjPnZ8TZMN7Ha+keZKbissVKNFBfXQ3MytQ31/79tjS1yUOcMuMmZ0WFJcI8CFnIXpxQoelxemN0hgSm1u0Z6wiD/ksKOk2FQeLpeuhejd6NfTpIQ6dVvFJZYpL+KGQhbwy7D98QxgatiC/6/g3o8C88G/9/rggaUnJg8msXDG8Bz2jc4X18t8leoLGJV2g=="
],
"x5t": "89b8Q_tnyMA9D6M_H5HyY51hbYc",
"x5t#S256": "w8sR66yFksSyqOJE9Aev6sX-stHbRaIyM1DhUe3zB_g"
},
{
"kid": "or06hiTwV9hLyp9giNGVs853jhHhEMRBbeD39fphP6w",
"kty": "EC",
"alg": "ES256",
"use": "sig",
"crv": "P-256",
"x": "y3jWqPjKVR_d-dzU-Zj5WEFClSd8uNKFew_MJ07HDTA",
"y": "WEVEjjM59EPhwCdI_X80Jzb8qJTV0Snlmnpgjqn2Y-o"
}
]
}    
""".trimIndent()