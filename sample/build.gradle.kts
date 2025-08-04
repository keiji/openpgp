plugins {
    id("java-library")
    kotlin("jvm") version "2.2.0"
}

group = "dev.keiji.openpgp"
version = "1.0-SNAPSHOT"

dependencies {
    implementation(project(":packet"))
    implementation(project(":signature-ext"))

    testImplementation("org.junit.jupiter:junit-jupiter-api:5.13.4")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.13.4")
}

tasks.getByName<Test>("test") {
    useJUnitPlatform()
}
