plugins {
    kotlin(PluginIds.KotlinKapt)
    kotlin(PluginIds.KotlinXSerialization) version PluginVersions.Kotlin
    `maven-publish`
    signing
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

signing {
    sign(publishing.publications)
}

publishing {
    repositories {
        maven {
            name = "OSSRH"
            url = uri(repoURL())
            credentials {
                username = System.getenv("OSSRH_USER")
                password = System.getenv("OSSRH_PASSWORD") 
            }
        }
    }

    publications {
        create<MavenPublication>("mavenJava") {
            pom {
                name.set("kjwt-core")
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
            artifactId = "kjwt-core"
            groupId = project.group.toString()
            version = project.version.toString()
            from(components["java"])
        }
    }
}