plugins {
    `java-library`
    alias(libs.plugins.kotlinx.serialization)
    id("kotlin-conventions")
    id("build-conventions")
    id("publishing-conventions")
}

dependencies {
    listOf(
        projects.core,
        platform(libs.arrow.stack),
        libs.kotlin.reflect,
        libs.kotlinLogging,
        libs.kotlinx.coroutines.core,
        libs.kotlinx.serialization.json,
    ).map {
        api(it)
    }

    api(libs.arrow.core)

    listOf(
        libs.kotest.runner,
        libs.kotest.assertions.core,
        libs.kotest.assertions.arrow,
        libs.logbackClassic,
    ).map {
        testImplementation(it)
    }
}