plugins {
    `java-library`
    kotlin(PluginIds.KotlinXSerialization) version PluginVersions.Kotlin
    `maven-publish`
}

dependencies {
    listOf(
        project(":core"),
        platform(Libraries.ArrowStack),
        Libraries.ArrowCore,
        Libraries.KotlinReflect,
        Libraries.KotlinXCoRoutinesCore,
        Libraries.KotlinXSerializationJSON,
    ).map {
        api(it)
    }

    listOf(
        Libraries.Kotest,
        Libraries.KotestAssertions,
        Libraries.KotestAssertionsArrow,
    ).map {
        testImplementation(it)
    }
}