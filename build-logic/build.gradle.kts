// force 1.6.10 otherwise we get 1.6.10 & 1.5.31 on the gradle classpath
buildscript {
    dependencies {
        classpath(libs.gradle.kotlin.jvm)
    }
}

plugins {
    base // required to resolve dependencies
}