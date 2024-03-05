import io.gitlab.arturbosch.detekt.Detekt
import io.gitlab.arturbosch.detekt.DetektCreateBaselineTask
import io.gitlab.arturbosch.detekt.report.ReportMergeTask
import org.jetbrains.dokka.gradle.DokkaTaskPartial

plugins {
    kotlin("jvm")
    id("org.jetbrains.dokka")
    id("io.gitlab.arturbosch.detekt")
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

val reportMerge by tasks.registering(ReportMergeTask::class) {
    output.set(rootProject.layout.buildDirectory.file("reports/detekt/detekt.xml"))
}

subprojects {
    apply(plugin = "io.gitlab.arturbosch.detekt")
    detekt {
        buildUponDefaultConfig = true
        allRules = true
        config.setFrom("$rootDir/config/detekt/detekt.yml")
        baseline = file("$rootDir/config/detekt/baseline.xml")
    }

    tasks.withType<Detekt>().configureEach {
        finalizedBy(reportMerge)
    }

    reportMerge {
        input.from(tasks.withType<Detekt>().map { it.xmlReportFile })
    }

    tasks.withType<Detekt>().configureEach {
        jvmTarget = JavaVersion.VERSION_1_8.toString()
    }
    tasks.withType<DetektCreateBaselineTask>().configureEach {
        jvmTarget = JavaVersion.VERSION_1_8.toString()
    }
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
