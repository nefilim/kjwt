import org.jetbrains.kotlin.gradle.tasks.KotlinCompile
import com.github.benmanes.gradle.versions.updates.DependencyUpdatesTask
import pl.allegro.tech.build.axion.release.domain.scm.ScmPosition
import pl.allegro.tech.build.axion.release.domain.properties.TagProperties

plugins {
    kotlin("jvm") version PluginVersions.Kotlin
    kotlin(PluginIds.KotlinKapt) version PluginVersions.Kotlin
    kotlin(PluginIds.KotlinXSerialization) version PluginVersions.Kotlin
    id(PluginIds.TaskTree) version PluginVersions.TaskTree
    id(PluginIds.TestLogger) version PluginVersions.TestLogger
    id(PluginIds.DependencyUpdates) version PluginVersions.DependencyUpdates
    id(PluginIds.Idea)
    id(PluginIds.AxionRelease) version PluginVersions.AxionRelease
    `maven-publish`
}

buildscript {
    repositories {
        gradlePluginPortal()
    }
}

scmVersion {
    tag.prefix = "v"
    tag.initialVersion = KotlinClosure2<TagProperties, ScmPosition, String>({ config, position -> "0.1.0" })
    versionIncrementer("incrementPatch")
}

group = "io.github.nefilim.kjwt"
version = scmVersion.version

repositories {
    mavenLocal()
    mavenCentral()
}

tasks.withType<JavaCompile> {
    sourceCompatibility = JavaVersion.VERSION_11.toString()
    targetCompatibility = sourceCompatibility
}

tasks.withType<KotlinCompile> {
    kotlinOptions {
        freeCompilerArgs = listOf("-Xjsr305=strict", "-Xinline-classes", "-Xopt-in=kotlin.RequiresOptIn")
        jvmTarget = "11"
        languageVersion = "1.5"
        apiVersion = "1.5"
    }
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

dependencies {
    listOf(
        platform(Libraries.ArrowStack),
        Libraries.ArrowCore,
        Libraries.KotlinLogging,
        Libraries.KotlinXCoRoutinesCore,
        Libraries.KotlinXSerializationJSON,
    ).map {
        implementation(it)
    }
    
    listOf(
        Libraries.Kotest,
        Libraries.KotestAssertions,
        Libraries.KotestAssertionsArrow,
        Libraries.NimbusJWT,
    ).map {
        testImplementation(it)
    }
}

publishing {
    repositories {
        maven {
            name = "OSSRH"
            setUrl("https://oss.sonatype.org/service/local/staging/deploy/maven2")
            credentials {
                username = System.getenv("OSSRH_USER") ?: return@credentials
                password = System.getenv("OSSRH_PASSWORD") ?: return@credentials
            }
        }
    }

    publications {
        create<MavenPublication>("mavenJava") {
            artifactId = project.name
            groupId = project.group.toString()
            version = project.version.toString()
            from(components["java"])
        }
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
