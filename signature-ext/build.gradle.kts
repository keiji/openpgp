plugins {
    id("java-library")
    kotlin("jvm") version "1.8.10"
    id("org.jetbrains.dokka")
    id("maven-publish")
    signing
}

val versionCode: String by rootProject.extra
val mavenGroupId: String by rootProject.extra

group = "dev.keiji.openpgp.signature.ext"
version = project.version

java {
    toolchain.languageVersion.set(JavaLanguageVersion.of(11))
    withSourcesJar()
}

tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile>().configureEach {
    kotlinOptions {
        jvmTarget = "11"
    }
}

dependencies {
    implementation(project(":packet"))

    // https://mvnrepository.com/artifact/org.bouncycastle/bcutil-jdk18on
    implementation("org.bouncycastle:bcutil-jdk18on:1.72")

    testImplementation("org.junit.jupiter:junit-jupiter-api:5.8.1")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.8.1")
}

tasks.getByName<Test>("test") {
    useJUnitPlatform()
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

publishing {
    publications {
        create<MavenPublication>("mavenJava") {
            groupId = mavenGroupId
            artifactId = "signature-ext"
            version = versionCode

            from(components["java"])
            artifact(dokkaJavadocJar)

            pom {
                name.set("OpenPGP certificate extensions")
                description.set("OpenPGP packet decoder/encoder for Kotlin")
                url.set("https://github.com/keiji/openpgp")
                licenses {
                    license {
                        name.set("The Apache License, Version 2.0")
                        url.set("http://www.apache.org/licenses/LICENSE-2.0.txt")
                    }
                }
                developers {
                    developer {
                        id.set("keiji")
                        name.set("ARIYAMA Keiji")
                        email.set("keiji.ariyama@gmail.com")
                    }
                }
                scm {
                    connection.set("scm:git://github.com/keiji/openpgp.git")
                    developerConnection.set("scm:git:ssh://github.com/keiji/openpgp.git")
                    url.set("https://github.com/keiji/openpgp")
                }
            }
        }
    }
    repositories {
        maven {
            val releasesRepoUrl = uri(layout.buildDirectory.dir("repos/releases"))
            val snapshotsRepoUrl = uri(layout.buildDirectory.dir("repos/snapshots"))
            url = if (version.toString().endsWith("SNAPSHOT")) snapshotsRepoUrl else releasesRepoUrl
        }
    }
}

signing {
    useGpgCmd()
    sign(publishing.publications["mavenJava"])
}