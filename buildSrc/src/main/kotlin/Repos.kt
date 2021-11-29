import org.gradle.api.Project

fun Project.repoURL(): String {
    return if (version.toString().endsWith("SNAPSHOT"))
        "https://s01.oss.sonatype.org/content/repositories/snapshots/"
    else
        "https://s01.oss.sonatype.org/service/local/staging/deploy/maven2/"
}