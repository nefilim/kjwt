rootProject.name = "kJWT"

pluginManagement {
    repositories {
        mavenLocal()
        gradlePluginPortal()
    }
}

include(
    "core",
    "google-kms-grpc",
)
