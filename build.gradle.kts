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
    maven {
        url = uri("https://dl.bintray.com/spekframework/spek")
    }
}

dependencies {
    val versions = mapOf(
            "kotlin" to "1.2.51",
            "junit" to "5.3.1",
            "junitPlatform" to "5.3.1",
            "jose4j" to "0.6.4",
            "mockito" to "2.23.0",
            "jBCrypt" to "0.4",
            "apacheHttpClient" to "4.5.6",
            "klaxon" to "3.0.1",
            "spek" to "2.0.0-rc.1"
    )

    implementation(kotlin("stdlib-jdk8"))
    implementation("org.bitbucket.b_c:jose4j:${versions["jose4j"]}")
    implementation("org.mindrot:jbcrypt:${versions["jBCrypt"]}")
    implementation("org.apache.httpcomponents:httpclient:${versions["apacheHttpClient"]}")

    testImplementation("org.junit.jupiter:junit-jupiter-api:${versions["junit"]}")
    testImplementation("org.junit.jupiter:junit-jupiter-params:${versions["junit"]}")
    testImplementation("org.mockito:mockito-core:${versions["mockito"]}")
    testImplementation("com.beust:klaxon:${versions["klaxon"]}")
    testImplementation("org.spekframework.spek2:spek-dsl-jvm:${versions["spek"]}") {
        exclude(group = "org.jetbrains.kotlin")
    }
    testImplementation("org.spekframework.spek2:spek-runner-junit5:${versions["spek"]}") {
        exclude(group = "org.junit.platform")
        exclude(group = "org.jetbrains.kotlin")
    }
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:${versions["junitPlatform"]}")
    testRuntimeOnly("org.jetbrains.kotlin:kotlin-reflect:${versions["kotlin"]}")
}

tasks.withType<KotlinCompile> {
    kotlinOptions.jvmTarget = "1.8"
}

tasks.withType<Test> {
    useJUnitPlatform {
        includeEngines("spek2")
    }
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