plugins {
    id("java-library")
    kotlin("jvm") version "2.2.21"
}

group = "dev.keiji.openpgp"
version = "1.0-SNAPSHOT"

dependencies {
    implementation(project(":packet"))
    implementation(project(":signature-ext"))

    testImplementation("org.junit.jupiter:junit-jupiter-api:6.0.3")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:6.0.3")
}

tasks.getByName<Test>("test") {
    useJUnitPlatform()
}
