# kJWT 

Functional Kotlin & Arrow based library for generating and verifying JWTs and JWSs.

* [JWS](https://datatracker.ietf.org/doc/html/rfc7515)
* [JWT](https://datatracker.ietf.org/doc/html/rfc7519)

The following [Algorithms](https://datatracker.ietf.org/doc/html/rfc7518) are supported:

* HS256
* HS384
* HS512
* RS256
* RS384
* RS512
* ES256  (secp256r1 curve)
* ES256K (secp256k1 curve)
* ES384
* ES512
     
# Usage

Include the following dependency: `io.github.nefilim.kjwt:kjwt-core:0.4.0` in your build. 

* Google KMS support also add: `io.github.nefilim.kjwt:kjwt-google-kms-grpc:0.4.0`. Documentation TODO. 
* minimal JWKS support also add: `io.github.nefilim.kjwt:kjwt-jwks:0.4.0`. Documentation TODO. See [JWKSSpec](https://github.com/nefilim/kjwt/blob/main/jwks/src/test/kotlin/io/github/nefilim/kjwt/jwks/JWKSpec.kt#L57-L81)

For examples see: [JWTSpec.kt](https://github.com/nefilim/kjwt/blob/main/core/src/test/kotlin/io/github/nefilim/kjwt/JWTSpec.kt) 

## Creating a JWT

```kotlin
val jwt = JWT.es256("kid-123") {
    subject("1234567890")
    issuer("nefilim")
    claim("name", "John Doe")
    claim("admin", true)
    issuedAt(LocalDateTime.ofInstant(Instant.ofEpochSecond(1516239022), ZoneId.of("UTC")))
}
```
will create the following:
```json
{
  "alg":"ES256",
  "typ":"JWT",
  "kid":"123"
}
{
    "sub": "1234567890",
    "iss": "nefilim",
    "name": "John Doe",
    "admin": true,
    "iat": 1516239022
}
```

# Signing a JWT
                  
Following on from above:

```kotlin
jwt.sign(ecPrivateKey)

```
returns an `Either<JWTVerificationError, SignedJWT<JWSES256Algorithm>>`. The `rendered` field in the `SignedJWT` 
contains the encoded string representation, in this case:

`eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEyMyJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaXNzIjoibmVmaWxpbSIsIm5hbWUiOiJKb2huIERvZSIsImFkbWluIjp0cnVlLCJpYXQiOjE1MTYyMzkwMjJ9.glaZCoqhNE7TiPLZl2hDK18yZGJUyVW0cE8pTM-zggyVfROiMPQJlImVcPSxTd50A8NRDOhoZwrqX04K4QS1bQ`
                         
# Decoding a JWT
           
```kotlin
JWT.decode("eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEyMyJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaXNzIjoibmVmaWxpbSIsIm5hbWUiOiJKb2huIERvZSIsImFkbWluIjp0cnVlLCJpYXQiOjE1MTYyMzkwMjJ9.glaZCoqhNE7TiPLZl2hDK18yZGJUyVW0cE8pTM-zggyVfROiMPQJlImVcPSxTd50A8NRDOhoZwrqX04K4QS1bQ")
```
If the algorithm is known and expected:

```kotlin
JWT.decodeT("eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIs...", JWSES256Algorithm)
```

The resulting `DecodedJWT` contains a `JWT<JWSES256Algorithm>` and the individual (3) parts of the JWT. Public 
claims can be accessed via the predefined accessors, eg:

```kotlin
JWT.decode("...").tap { 
    println("the issuer is: ${it.issuer()}")
    println("the subject is: ${it.subject()}")
}
```

private claims be accessed with 
 * `claimValue`
 * `claimValueAsBoolean`
 * `claimValueAsLong` 

etc.

# Validating a JWT

Custom claim validators can be created by defining `ClaimsValidator`:

```kotlin
typealias ClaimsValidatorResult = ValidatedNel<out JWTVerificationError, JWTClaims>
typealias ClaimsValidator = (JWTClaims) -> ClaimsValidatorResult
```

eg. a claim validator for issuer could look like this:

```kotlin
fun issuer(issuer: String): ClaimsValidator = requiredOptionClaim( // an absent claim would be considered an error
    "issuer", // a label for the claim (used in error reporting) 
    { issuer() }, // a function that returns the claim from the JWTClaims/JWT 
    { it == issuer }, // the predicate to evaluate the claim value 
    JWTValidationError.InvalidIssuer // the error to return 
)
```
                                                            
and for a private claim:

```kotlin
fun issuer(issuer: String): ClaimsValidator = requiredOptionClaim( // an absent claim would be considered an error
    "admin", // a label for the claim (used in error reporting) 
    { claimValueAsBoolean("admin") }, // a function that returns the claim from the JWTClaims/JWT 
    { it == true }, // the predicate to evaluate the claim value 
)
```

in this case the `ValidationNel` would contain `JWTValidationError.RequiredClaimIsMissing("admin")` if the claim was 
absent in the JWT or `JWTValidationError.RequiredClaimIsInvalid("admin")` in case it predicate failed (the value was false).

`ClaimValidator`s can be composed using `fun validateClaims(...)`, eg:

```kotlin
fun standardValidation(claims: JWTClaims): ValidatedNel<out JWTVerificationError, JWTClaims> =
    validateClaims(notBefore, expired, issuer("thecompany"), subject("1234567890"), audience("http://thecompany.com"))
(claims)
```

Predefined claim validators are bundled for these public claims:
* issuer
* subject
* audience
* expired
* notbefore

# Verifying a Signature

```kotlin
verifySignature<JWSRSAAlgorithm>("eyJhbGci...", publicKey)
```

Not the type needs to be specified explicitly and will limit the publicKey parameter to the allowable types. Eg, in 
this case it must be an `RSAPublicKey`.

# Claim Validation and Verifying together
                                                     
Combining claim validation and signature verification into one step can be done using the corresponding `fun verify(...)` (once again, the type parameter is required):
                       
```kotlin
val standardValidation: ClaimsValidator = { claims ->
    validateClaims(
        notBefore, 
        expired, 
        issuer("thecompany"), 
        subject("1234567890"), 
        audience("http://thecompany.com")
    )(claims)
}

verify<JWSES256Algorithm>("eyJhbGci...", publicKey, standardValidation)
```
    
The resulting `typealias ClaimsValidatorResult = ValidatedNel<out JWTVerificationError, JWTClaims>` will either 
contain all the validation problems or the valid JWT.
