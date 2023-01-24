plugins {
    id("java-library")
    kotlin("jvm") version "1.8.0"
}

group = "dev.keiji.openpgp.packet"

repositories {
    mavenCentral()
}

dependencies {
    implementation(kotlin("stdlib"))

    api(project(mapOf("path" to ":core")))
    implementation(project(mapOf("path" to ":common")))

    implementation("dev.keiji.rfc4648:rfc4648:1.1.0")

    testImplementation("org.junit.jupiter:junit-jupiter-api:5.9.2")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.9.2")
}

tasks.getByName<Test>("test") {
    useJUnitPlatform()
}