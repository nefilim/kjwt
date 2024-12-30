enableFeaturePreview("TYPESAFE_PROJECT_ACCESSORS")

rootProject.name = "kJWT"

pluginManagement {
    repositories {
        mavenLocal()
        gradlePluginPortal()
    }
    includeBuild("build-logic")
}

plugins {
    // See https://jmfayard.github.io/refreshVersions
    id("de.fayard.refreshVersions") version "0.60.5"
}

include(
    "core",
    "google-kms-grpc",
    "jwks",
)

refreshVersions {
    // work-around https://github.com/Splitties/refreshVersions/issues/640
    file("build/tmp/refreshVersions").mkdirs()
    versionsPropertiesFile = file("build/tmp/refreshVersions/versions.properties")

    rejectVersionIf {
        candidate.stabilityLevel.isLessStableThan(current.stabilityLevel)
    }
}
