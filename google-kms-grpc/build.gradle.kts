import com.google.protobuf.gradle.generateProtoTasks
import com.google.protobuf.gradle.id
import com.google.protobuf.gradle.plugins
import com.google.protobuf.gradle.protobuf
import com.google.protobuf.gradle.protoc

plugins {
    `java-library`
    alias(libs.plugins.protobuf)
    id("kotlin-conventions")
    id("build-conventions")
    id("publishing-conventions")
}

dependencies {
    protobuf(libs.google.kms.protobuf)
    listOf(
        projects.core,
        platform(libs.arrow.stack),
        libs.arrow.core,
        libs.grpc.protobuf,
        libs.grpc.stub,
        libs.grpc.stubKotlin,
        libs.protobuf.javautil,
        libs.protobuf.kotlin,
    ).map {
        api(it)
    }

    listOf(
        libs.kotest.runner,
        libs.kotest.assertions.core,
        libs.kotest.assertions.arrow,
    ).map {
        testImplementation(it)
    }
}

protobuf {
    protoc {
        artifact = libs.protobuf.protoc.get().toString()
    }
    plugins {
        id("grpc") {
            artifact = libs.grpc.protoc.java.get().toString()
        }
        id("grpckt") {
            artifact = "io.grpc:protoc-gen-grpc-kotlin:1.2.0:jdk7@jar" // libs.grpc.protoc.kotlin.get().toString()
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