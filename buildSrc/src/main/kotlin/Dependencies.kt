object PluginIds { // please keep this sorted in sections
    // Kotlin
    const val Kotlin = "kotlin"
    const val KotlinKapt = "kapt"
    const val KotlinXSerialization = "plugin.serialization"

    // 3rd Party
    const val DependencyUpdates = "com.github.ben-manes.versions"
    const val GitHubRelease = "com.github.breadmoirai.github-release"
    const val GradleNexusPublish = "io.github.gradle-nexus.publish-plugin"
    const val Idea = "idea"
    const val Protobuf = "com.google.protobuf"
    const val SemVer = "io.github.nefilim.gradle.semver-plugin"
    const val TaskTree = "com.dorongold.task-tree"
    const val TestLogger = "com.adarshr.test-logger"
}

object PluginVersions { // please keep this sorted in sections
    // Kotlin
    const val Kotlin = "1.6.0"

    // 3rd Party
    const val DependencyUpdates = "0.39.0"
    const val GitHub = "2.2.12"
    const val GradleNexusPublish = "1.1.0"
    const val Protobuf = "0.8.18"
    const val SemVer = "0.0.5"
    const val TaskTree = "2.1.0"
    const val TestLogger = "3.1.0"
}

object Versions {
    // kotlin
    const val Kotlin = PluginVersions.Kotlin
    const val KotlinXCoroutines = "1.5.2"
    const val KotlinXSerialization = "1.3.1"

    // 3rd Party
    const val Arrow = "1.0.1"
    const val GoogleKMSProtobuf = "0.94.0"
    const val GRPC = "1.42.1"
    const val GRPCKotlin = "1.2.0"
    const val Kotest = "5.0.1"
    const val KotestExtensionsArrow = "1.2.0"
    const val KotlinLogging = "2.1.0"
    const val Logback = "1.2.6"
    const val Nimbus = "9.15.2"
    const val Protobuf = "3.19.1"
    const val SLF4J = "1.7.30"
}

object Libraries {
    // Kotlin
    const val KotlinReflect = "org.jetbrains.kotlin:kotlin-reflect:${Versions.Kotlin}"
    const val KotlinXCoRoutinesCore = "org.jetbrains.kotlinx:kotlinx-coroutines-core:${Versions.KotlinXCoroutines}"
    const val KotlinXSerializationJSON = "org.jetbrains.kotlinx:kotlinx-serialization-json:${Versions.KotlinXSerialization}"

    // 3rd Party
    const val ArrowStack = "io.arrow-kt:arrow-stack:${Versions.Arrow}"
    const val ArrowCore = "io.arrow-kt:arrow-core"

    const val GoogleKMSProtobuf = "com.google.api.grpc:proto-google-cloud-kms-v1:${Versions.GoogleKMSProtobuf}"
    object GRPC {
        const val Protobuf = "io.grpc:grpc-protobuf:${Versions.GRPC}"
        const val ProtocJava = "io.grpc:protoc-gen-grpc-java:${Versions.GRPC}"
        const val ProtocKotlin = "io.grpc:protoc-gen-grpc-kotlin:${Versions.GRPCKotlin}:jdk7@jar"
        const val Stub = "io.grpc:grpc-stub:${Versions.GRPC}"
        const val StubKotlin = "io.grpc:grpc-kotlin-stub:${Versions.GRPCKotlin}"
    }
    object Protobuf {
        const val JavaUtil = "com.google.protobuf:protobuf-java-util:${Versions.Protobuf}"
        const val Kotlin = "com.google.protobuf:protobuf-kotlin:${Versions.Protobuf}"
        const val Protoc = "com.google.protobuf:protoc:${Versions.Protobuf}"
    }

    const val NimbusJWT = "com.nimbusds:nimbus-jose-jwt:${Versions.Nimbus}"

    const val Kotest = "io.kotest:kotest-runner-junit5-jvm:${Versions.Kotest}"
    const val KotestAssertions = "io.kotest:kotest-assertions-core-jvm:${Versions.Kotest}"
    const val KotestAssertionsArrow = "io.kotest.extensions:kotest-assertions-arrow:${Versions.KotestExtensionsArrow}"

    const val KotlinLogging = "io.github.microutils:kotlin-logging-jvm:${Versions.KotlinLogging}"
    const val LogbackClassic = "ch.qos.logback:logback-classic:${Versions.Logback}"

    const val SLF4JAPI = "org.slf4j:slf4j-api:${Versions.SLF4J}"
}