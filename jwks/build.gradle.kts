plugins {
    `java-library`
    alias(libs.plugins.kotlinx.serialization)
    `maven-publish`
}

dependencies {
    listOf(
        project(":core"),
        platform(libs.arrow.stack),
        libs.arrow.core,
        libs.kotlin.reflect,
        libs.kotlinx.coroutines.core,
        libs.kotlinx.serialization.json,
    ).map {
        api(it)
    }

    listOf(
        libs.kotest.runner,
        libs.kotest.assertions.core,
        libs.kotest.assertions.arrow,
        libs.kotlinLogging,
        libs.logbackClassic,
    ).map {
        testImplementation(it)
    }
}