plugins {
    `kotlin-dsl`
}

dependencies {
    implementation(libs.gradle.semver) // controls the version of the plugin used in the convention script plugin
    implementation(libs.gradle.testlogger) // controls the version of the plugin used in the convention script plugin
    implementation(libs.gradle.nexusPublish) // controls the version of the plugin used in the convention script plugin
    implementation(libs.gradle.kotlin.jvm) // controls the version of the plugin used in the convention script plugin
    implementation(libs.kotlin.gradle)
}