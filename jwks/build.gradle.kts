plugins {
    `java-library`
    kotlin(PluginIds.KotlinXSerialization) version PluginVersions.Kotlin
    `maven-publish`
    signing
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

signing {
    useInMemoryPgpKeys(
        System.getenv("SIGNING_KEY_ID"),
        System.getenv("SIGNING_KEY"),
        System.getenv("SIGNING_KEY_PASSPHRASE"),
    )
    val skipSigning = findProperty("skipSigning")?.let { (it as String).toBoolean() } ?: false
    if (!skipSigning)
        sign(publishing.publications)
    else {
        logger.warn("skipping signing")
    }
}

publishing {
    publications {
        create<MavenPublication>("mavenJava") {
            pom {
                name.set("kjwt-jwks")
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
            artifactId = "kjwt-jwks"
            groupId = project.group.toString()
            version = project.version.toString()
            from(components["java"])
        }
    }
}