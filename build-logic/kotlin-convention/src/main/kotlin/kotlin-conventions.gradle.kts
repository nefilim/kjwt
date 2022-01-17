import buildtools.dependency
import buildtools.libsCatalog
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    kotlin("jvm")
    `java-library`
}

val invalidQualifiers = setOf("alpha", "beta", "rc", "nightly")
@Suppress("UnstableApiUsage")
val kotlinVersion = project.libsCatalog.dependency("gradle-kotlin-jvm").get().versionConstraint.requiredVersion
configurations.all {
    resolutionStrategy {
        eachDependency {
            if (requested.group == "org.jetbrains.kotlin") {
                useVersion(kotlinVersion)
            }
        }
        componentSelection {
            all {
                if (invalidQualifiers.any { candidate.version.contains(it) })
                    reject("invalid qualifier versions for $candidate")
            }
        }
    }
}

val jvmVersion = 11
java {
    withSourcesJar()
    withJavadocJar()

    toolchain {
        languageVersion.set(JavaLanguageVersion.of(jvmVersion))
    }
}

tasks {
    withType<Test>() {
        maxParallelForks = Runtime.getRuntime().availableProcessors()
        useJUnitPlatform()
        testLogging {
            setExceptionFormat("full")
            setEvents(listOf("passed", "skipped", "failed", "standardOut", "standardError"))
        }
    }

    withType<KotlinCompile>() {
        kotlinOptions {
            freeCompilerArgs = listOf("-Xjsr305=strict", "-Xopt-in=kotlin.RequiresOptIn")
            languageVersion = "1.6"
            apiVersion = "1.6"
            jvmTarget = "$jvmVersion"
        }
    }
}