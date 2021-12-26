plugins {
    alias(libs.plugins.kotlinx.serialization)
    `maven-publish`
}

dependencies {
    listOf(
        platform(libs.arrow.stack),
        libs.arrow.core,
        libs.kotlinLogging,
        libs.kotlin.reflect,
        libs.kotlinx.coroutines.core,
        libs.kotlinx.serialization.json,
    ).map {
        implementation(it)
    }
    
    listOf(
        libs.kotest.runner,
        libs.kotest.assertions.core,
        libs.kotest.assertions.arrow,
        libs.nimbus,
    ).map {
        testImplementation(it)
    }
}