pluginManagement {
    plugins {
        kotlin("jvm") version "2.0.21"
        id("org.jetbrains.dokka") version "1.9.20"
        id("io.gitlab.arturbosch.detekt") version "1.23.6"
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
