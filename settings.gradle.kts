pluginManagement {
    plugins {
        kotlin("jvm") version "2.2.21"
        id("org.jetbrains.dokka") version "2.1.0"
        id("io.gitlab.arturbosch.detekt") version "1.23.8"
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
