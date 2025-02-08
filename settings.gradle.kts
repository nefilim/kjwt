enableFeaturePreview("TYPESAFE_PROJECT_ACCESSORS")

rootProject.name = "kJWT"

pluginManagement {
    repositories {
        mavenLocal()
        gradlePluginPortal()
    }
    includeBuild("build-logic")
}

include(
    "core",
    "google-kms-grpc",
    "jwks",
)
