import org.jetbrains.dokka.gradle.DokkaTaskPartial

plugins {
    kotlin("jvm")
    id("org.jetbrains.dokka")
}

buildscript {
    extra["mavenGroupId"] = "dev.keiji.openpgp"

    extra["versionCode"] = "0.0.1"
}

val exclude_dokka_modules = listOf("common", "core", "sample")

subprojects {
    if (exclude_dokka_modules.contains(name)) {
        return@subprojects
    }

    apply(plugin = "org.jetbrains.dokka")

    tasks.withType<DokkaTaskPartial>().configureEach {
        dokkaSourceSets.configureEach {
            documentedVisibilities.set(
                setOf(
                    org.jetbrains.dokka.DokkaConfiguration.Visibility.PUBLIC,
                    org.jetbrains.dokka.DokkaConfiguration.Visibility.PROTECTED
                )
            )
        }
    }
}

tasks.dokkaHtmlMultiModule {
    outputDirectory.set(File("${rootProject.buildDir}/javadoc"))
    moduleName.set("Dokka MultiModule Example")
}

val dokkaJavadocJar by tasks.register<Jar>("dokkaJavadocJar") {
    dependsOn(tasks.dokkaJavadoc)
    from(tasks.dokkaJavadoc.flatMap { it.outputDirectory })
    archiveClassifier.set("javadoc")
}

val dokkaHtmlJar by tasks.register<Jar>("dokkaHtmlJar") {
    dependsOn(tasks.dokkaHtml)
    from(tasks.dokkaHtml.flatMap { it.outputDirectory })
    archiveClassifier.set("htmldoc")
}
