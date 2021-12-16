import org.jetbrains.kotlin.gradle.tasks.KotlinCompile
import com.github.benmanes.gradle.versions.updates.DependencyUpdatesTask

plugins {
    kotlin("jvm") version PluginVersions.Kotlin
    kotlin(PluginIds.KotlinKapt) version PluginVersions.Kotlin
    id(PluginIds.TaskTree) version PluginVersions.TaskTree
    id(PluginIds.TestLogger) version PluginVersions.TestLogger
    id(PluginIds.DependencyUpdates) version PluginVersions.DependencyUpdates
    id(PluginIds.Idea)
    id(PluginIds.SemVer) version PluginVersions.SemVer
    id(PluginIds.GradleNexusPublish) version PluginVersions.GradleNexusPublish
    id(PluginIds.GitHubRelease) version PluginVersions.GitHubRelease
    `maven-publish`
    signing 
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

nexusPublishing {
    repositories {
        sonatype {
            username.set(System.getenv("OSS_USER"))
            password.set(System.getenv("OSS_TOKEN"))
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
        plugin("signing")
        plugin("maven-publish")
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

    signing {
        val skipSigning = findProperty("skipSigning")?.let { (it as String).toBoolean() } ?: false
        if (!skipSigning) {
            val signingKeyId: String? by project
            val signingKey: String? by project
            val signingPassword: String? by project
            useInMemoryPgpKeys(signingKeyId, signingKey, signingPassword)
            sign(publishing.publications)
        } else {
            logger.warn("skipping signing")
        }
    }

    publishing {
        publications {
            create<MavenPublication>("mavenJava") {
                pom {
                    name.set("kjwt-${project.name}")
                    description.set("Functional Kotlin & Arrow based library for generating and verifying JWTs and JWSs")
                    url.set("https://github.com/nefilim/kjwt")
                    licenses {
                        license {
                            name.set("GPL-3.0-only")
                            url.set("https://opensource.org/licenses/GPL-3.0")
                        }
                    }
                    developers {
                        developer {
                            id.set("nefilim")
                            name.set("nefilim")
                            email.set("nefilim@hotmail.com")
                        }
                    }
                    scm {
                        connection.set("scm:git:https://github.com/nefilim/kjwt.git")
                        url.set("https://github.com/nefilim/kjwt")
                    }
                }
                artifactId = "kjwt-${project.name}"
                groupId = project.group.toString()
                version = project.version.toString()
                from(components["java"])
            }
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