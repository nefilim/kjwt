import com.google.protobuf.gradle.generateProtoTasks
import com.google.protobuf.gradle.id
import com.google.protobuf.gradle.plugins
import com.google.protobuf.gradle.protobuf
import com.google.protobuf.gradle.protoc

plugins {
    `java-library`
    id(PluginIds.Protobuf) version PluginVersions.Protobuf
    `maven-publish`
    signing
}

dependencies {
    protobuf(Libraries.GoogleKMSProtobuf)
    listOf(
        project(":core"),
        platform(Libraries.ArrowStack),
        Libraries.ArrowCore,
        Libraries.GRPC.Auth,
        Libraries.GRPC.Protobuf,
        Libraries.GRPC.Stub,
        Libraries.GRPC.StubKotlin,
        Libraries.Protobuf.Kotlin,
        Libraries.Protobuf.JavaUtil,
        Libraries.KotlinLogging,
        Libraries.LogbackClassic,
        Libraries.KotlinXCoRoutinesCore,
    ).map {
        implementation(it)
    }

    runtimeOnly(Libraries.GRPC.Netty)
}

protobuf {
    protoc {
        artifact = Libraries.Protobuf.Protoc
    }
    plugins {
        id("grpc") {
            artifact = Libraries.GRPC.ProtocJava
        }
        id("grpckt") {
            artifact = Libraries.GRPC.ProtocKotlin
        }
    }
    generateProtoTasks {
        all().forEach {
            it.plugins {
                id("grpc")
                id("grpckt")
            }
            it.builtins {
                id("kotlin")
            }
        }
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
                name.set("kJWT")
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
            artifactId = "kjwt-google-kms"
            groupId = project.group.toString()
            version = project.version.toString()
            from(components["java"])
        }
    }
}