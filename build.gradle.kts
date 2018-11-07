import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    java
    kotlin("jvm") version "1.2.51"
    id("jacoco")
}

group = "io.imulab"
version = "0.0.1-SNAPSHOT"

repositories {
    jcenter()
    mavenCentral()
}

dependencies {
    val versions = mapOf(
            "junit" to "5.3.1",
            "junitPlatform" to "5.3.1",
            "jose4j" to "0.6.4",
            "mockito" to "2.23.0",
            "jBCrypt" to "0.4",
            "apacheHttpClient" to "4.5.6",
            "klaxon" to "3.0.1"
    )

    compile(kotlin("stdlib-jdk8"))
    compile("org.bitbucket.b_c:jose4j:${versions["jose4j"]}")
    compile("org.mindrot:jbcrypt:${versions["jBCrypt"]}")
    compile("org.apache.httpcomponents:httpclient:${versions["apacheHttpClient"]}")

    testCompile("org.junit.jupiter:junit-jupiter-api:${versions["junit"]}")
    testCompile("org.junit.jupiter:junit-jupiter-params:${versions["junit"]}")
    testCompile("org.mockito:mockito-core:${versions["mockito"]}")
    testCompile("com.beust:klaxon:${versions["klaxon"]}")

    runtime("org.junit.jupiter:junit-jupiter-engine:${versions["junitPlatform"]}")
}

tasks.withType<KotlinCompile> {
    kotlinOptions.jvmTarget = "1.8"
}

tasks.withType<Test> {
    useJUnitPlatform()
}

tasks.withType<JacocoReport> {
    reports {
        html.apply {
            isEnabled = true
        }
        xml.apply {
            isEnabled = true
        }
    }
}

jacoco {
    toolVersion = "0.8.2"
}