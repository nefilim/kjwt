import buildtools.dependency
import buildtools.libsCatalog
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile
import org.gradle.kotlin.dsl.assign
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    kotlin("jvm")
    `java-library`
}

val invalidQualifiers = setOf("alpha", "beta", "rc", "nightly")
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

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_11)
        freeCompilerArgs.add("-Xjsr305=strict")
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
}