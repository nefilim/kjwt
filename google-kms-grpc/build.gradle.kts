import com.google.protobuf.gradle.generateProtoTasks
import com.google.protobuf.gradle.id
import com.google.protobuf.gradle.plugins
import com.google.protobuf.gradle.protobuf
import com.google.protobuf.gradle.protoc

plugins {
    `java-library`
    id(PluginIds.Protobuf) version PluginVersions.Protobuf
    `maven-publish`
}

dependencies {
    protobuf(Libraries.GoogleKMSProtobuf)
    listOf(
        project(":core"),
        platform(Libraries.ArrowStack),
        Libraries.ArrowCore,
        Libraries.GRPC.Protobuf,
        Libraries.GRPC.Stub,
        Libraries.GRPC.StubKotlin,
        Libraries.Protobuf.Kotlin,
        Libraries.Protobuf.JavaUtil,
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