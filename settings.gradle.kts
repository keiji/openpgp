pluginManagement {
    plugins {
        kotlin("jvm") version "1.8.10"
        id("org.jetbrains.dokka") version "1.9.20"
        id("io.gitlab.arturbosch.detekt") version "1.23.5"
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        mavenCentral()
    }
}

rootProject.name = "OpenPgp"
include(
    ":common",
    ":packet",
    ":signature-ext",
    ":sample",
)
