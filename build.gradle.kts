import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    kotlin("jvm") version "1.2.51"
}

group = "io.imulab"
version = "0.0.1-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    val versions = mapOf(
            "junit" to "5.0.0",
            "junitPlatform" to "1.0.0"
    )

    compile(kotlin("stdlib-jdk8"))

    testCompile("org.junit.jupiter:junit-jupiter-api:${versions["junit"]}")

    runtime("org.junit.jupiter:junit-jupiter-engine:${versions["junitPlatform"]}\"")
}

tasks.withType<KotlinCompile> {
    kotlinOptions.jvmTarget = "1.8"
}