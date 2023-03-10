pluginManagement {
    plugins {
        kotlin("jvm") version "1.8.10"
        id("org.jetbrains.dokka") version "1.8.10"
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
    ":core",
    ":common",
    ":packet",
    ":signature-ext",
    ":sample",
)
