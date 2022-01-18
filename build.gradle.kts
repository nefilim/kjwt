import com.github.benmanes.gradle.versions.updates.DependencyUpdatesTask

plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.tasktree)
    alias(libs.plugins.semver)
    alias(libs.plugins.nexus.publish)
    alias(libs.plugins.dependencyUpdates)
    alias(libs.plugins.dependencyCheck)
    alias(libs.plugins.githubRelease)
    `maven-publish`
    id("build-conventions")
}

repositories {
    mavenLocal()
    mavenCentral()
}

dependencyCheck {
    failOnError = true

    suppressionFile = ".dependency-check-suppression.xml"
    analyzers.experimentalEnabled = false
    analyzers.assemblyEnabled = false
    analyzers.msbuildEnabled = false
    analyzers.nuspecEnabled = false
    analyzers.nugetconfEnabled = false
    analyzers.pyPackageEnabled = false
    analyzers.pyDistributionEnabled = false
    analyzers.rubygemsEnabled = false
}

// can only be applied to root project 
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

val githubTokenValue = findProperty("githubToken")?.toString() ?: System.getenv("GITHUB_TOKEN")
githubRelease {
    token(githubTokenValue) // This is your personal access token with Repo permissions
    // You get this from your user settings > developer settings > Personal Access Tokens
    owner("nefilim") // default is the last part of your group. Eg group: "com.github.breadmoirai" => owner: "breadmoirai"
    repo("kjwt") // by default this is set to your project name
    tagName(semver.versionTagName()) // by default this is set to "v${project.version}"
    targetCommitish("main") // by default this is set to "master"
    body(changelog())
    draft(false) // by default this is false
    prerelease(false) // by default this is false

    overwrite(false) // by default false; if set to true, will delete an existing release with the same tag and name
    dryRun(false) // by default false; you can use this to see what actions would be taken without making a release
    apiEndpoint("https://api.github.com") // should only change for github enterprise users
    client // This is the okhttp client used for http requests
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