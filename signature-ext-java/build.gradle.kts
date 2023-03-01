plugins {
    id("java-library")
    kotlin("jvm") version "1.8.0"
}

group = "dev.keiji.openpgp"

repositories {
    mavenCentral()
}

dependencies {
    implementation(kotlin("stdlib"))

    implementation(project(mapOf("path" to ":common")))
    implementation(project(mapOf("path" to ":packet")))

    testImplementation("org.junit.jupiter:junit-jupiter-api:5.8.1")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.8.1")
}

tasks.getByName<Test>("test") {
    useJUnitPlatform()
}
