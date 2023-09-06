plugins {
    alias(libs.plugins.kotlinx.serialization)
    id("kotlin-conventions")
    id("build-conventions")
    id("publishing-conventions")
}

dependencies {
    listOf(
        platform(libs.arrow.stack),
        libs.kotlinLogging,
        libs.kotlin.reflect,
        libs.kotlinx.coroutines.core,
        libs.kotlinx.serialization.json,
    ).map {
        implementation(it)
    }

    api(libs.arrow.core)

    listOf(
        libs.kotest.runner,
        libs.kotest.assertions.core,
        libs.kotest.assertions.arrow,
        libs.nimbus,
    ).map {
        testImplementation(it)
    }
}