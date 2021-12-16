plugins {
    kotlin(PluginIds.KotlinKapt)
    kotlin(PluginIds.KotlinXSerialization) version PluginVersions.Kotlin
    `maven-publish`
}

dependencies {
    listOf(
        platform(Libraries.ArrowStack),
        Libraries.ArrowCore,
        Libraries.KotlinLogging,
        Libraries.KotlinReflect,
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