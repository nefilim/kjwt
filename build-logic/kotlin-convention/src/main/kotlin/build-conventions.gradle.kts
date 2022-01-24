plugins {
    id("io.github.nefilim.gradle.semver-plugin") // version controlled by the dependency for this build
    id("com.adarshr.test-logger")
}

semver {
    verbose(true)
    tagPrefix("v")
    initialVersion("0.0.1")
    featureBranchRegex(listOf("[a-zA-Z\\-_0-9]+\\/sc-\\d+\\/[a-zA-Z\\-_0-9]+"))
    findProperty("semver.overrideVersion")?.toString()?.let { overrideVersion(it) }

    currentBranch {
        scope(findProperty("semver.currentBranch.scope")?.toString())
        stage(findProperty("semver.currentBranch.stage")?.toString())
    }
}

group = "io.github.nefilim.kjwt"
version = semver.version.value

configure<com.adarshr.gradle.testlogger.TestLoggerExtension> {
    theme = com.adarshr.gradle.testlogger.theme.ThemeType.STANDARD
    showCauses = true
    slowThreshold = 1000
    showSummary = true
    showStandardStreams = true
}

