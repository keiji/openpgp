plugins {
    id("java-library")
    kotlin("jvm") version "1.8.10"
    id("org.jetbrains.dokka")
    id("maven-publish")
}

val versionCode: String by rootProject.extra
val mavenGroupId: String by rootProject.extra

group = "dev.keiji.openpgp"
version = project.version

java {
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
    withSourcesJar()
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

dependencies {
    // https://mvnrepository.com/artifact/org.apache.commons/commons-compress
    implementation("org.apache.commons:commons-compress:1.22")

    testImplementation("org.junit.jupiter:junit-jupiter-api:5.9.2")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.9.2")
}

tasks.getByName<Test>("test") {
    useJUnitPlatform()
}

publishing {
    publications {
        register<MavenPublication>("mavenJava") {
            groupId = mavenGroupId
            artifactId = "common"
            version = versionCode

            from(components["java"])
            artifact(dokkaJavadocJar)

            pom {
                name.set("OpenPGP")
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

//signing {
//    useGpgCmd()
//    sign(publishing.publications["mavenJava"])
//}
