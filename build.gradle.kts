import org.jetbrains.kotlin.gradle.tasks.KotlinCompile
import com.github.benmanes.gradle.versions.updates.DependencyUpdatesTask

plugins {
    kotlin("jvm") version PluginVersions.Kotlin
    kotlin(PluginIds.KotlinKapt) version PluginVersions.Kotlin
    id(PluginIds.TaskTree) version PluginVersions.TaskTree
    id(PluginIds.TestLogger) version PluginVersions.TestLogger
    id(PluginIds.DependencyUpdates) version PluginVersions.DependencyUpdates
    id(PluginIds.Idea)
    id(PluginIds.Reckon) version PluginVersions.Reckon
    id(PluginIds.GradleNexusPublish) version PluginVersions.GradleNexusPublish
}

buildscript {
    repositories {
        gradlePluginPortal()
    }
}

repositories {
    mavenLocal()
    mavenCentral()
}

reckon {
    scopeFromProp()
    stageFromProp("milestone", "rc", "final")
}

nexusPublishing {
    repositories {
        sonatype {  
            nexusUrl.set(uri("https://s01.oss.sonatype.org/service/local/"))
            snapshotRepositoryUrl.set(uri("https://s01.oss.sonatype.org/content/repositories/snapshots/"))
        }
    }
}

allprojects {
    apply(plugin = PluginIds.DependencyUpdates)

    group = "io.github.nefilim.kjwt"

    tasks.withType<JavaCompile> {
        sourceCompatibility = JavaVersion.VERSION_11.toString()
        targetCompatibility = sourceCompatibility
    }

    tasks.withType<KotlinCompile> {
        kotlinOptions {
            freeCompilerArgs = listOf("-Xjsr305=strict", "-Xopt-in=kotlin.RequiresOptIn")
            jvmTarget = "11"
            languageVersion = "1.6"
            apiVersion = "1.6"
        }
    }
}

subprojects {
    // https://kotlinlang.org/docs/reference/using-gradle.html#using-gradle-kotlin-dsl
    apply {
        plugin(PluginIds.Kotlin)
        plugin(PluginIds.Idea)
        plugin(PluginIds.TestLogger)
    }

    java {
        withSourcesJar()
        withJavadocJar()
    }

    repositories {
        mavenLocal()
        mavenCentral()
    }

    configure<com.adarshr.gradle.testlogger.TestLoggerExtension> {
        theme = com.adarshr.gradle.testlogger.theme.ThemeType.STANDARD
        showCauses = true
        slowThreshold = 1000
        showSummary = true
    }

    tasks.withType<Test> {
        useJUnitPlatform()
    }
}

fun isNonStable(version: String): Boolean {
    val stableKeyword = listOf("RELEASE", "FINAL", "GA").any { version.toUpperCase().contains(it) }
    val regex = "^[0-9,.v-]+(-r)?$".toRegex()
    val isStable = stableKeyword || regex.matches(version)
    return isStable.not()
}

// https://github.com/ben-manes/gradle-versions-plugin/discussions/482
tasks.named<DependencyUpdatesTask>("dependencyUpdates").configure {
    // reject all non stable versions
    rejectVersionIf {
        isNonStable(candidate.version)
    }
}