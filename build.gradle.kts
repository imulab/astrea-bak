import com.github.jengelman.gradle.plugins.shadow.tasks.ShadowJar
import groovy.lang.GroovyObject
import org.gradle.api.internal.tasks.testing.junitplatform.JUnitPlatformTestFramework
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile
import org.jfrog.gradle.plugin.artifactory.dsl.PublisherConfig
import org.jfrog.gradle.plugin.artifactory.dsl.ResolverConfig

val astrea = "astrea"

fun requireEnv(name: String, hard: Boolean = false): String {
    return if (System.getenv(name) == null) {
        val message = "Environment variable $name not set."
        if (!hard) {
            System.out.println(message)
            ""
        } else
            throw IllegalStateException(message)
    } else {
        System.getenv(name)
    }
}

group = "io.imulab"
version = "0.8.1"

repositories {
    jcenter()
    mavenCentral()
    maven {
        url = uri("https://dl.bintray.com/spekframework/spek")
    }
}

plugins {
    java
    kotlin("jvm") version "1.2.51"
    id("jacoco")
    `maven-publish`
    id("com.github.johnrengelman.shadow") version "2.0.2"
    id("com.jfrog.artifactory") version "4.8.1"
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
            "spek" to "2.0.0-rc.1",
            "assertj" to "3.11.1"
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
    testImplementation("org.assertj:assertj-core:${versions["assertj"]}")
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

val shadowJar: ShadowJar by tasks
tasks.withType<ShadowJar> {
    baseName = astrea
    classifier = ""
}

publishing {
    (publications) {
        astrea(MavenPublication::class) {
            artifactId = astrea
            artifact(shadowJar)
            pom {
                withXml {
                    asNode().appendNode("dependencies").let { depNode ->
                        configurations.compile.allDependencies.forEach {
                            depNode.appendNode("dependency").apply {
                                appendNode("groupId", it.group)
                                appendNode("artifactId", it.name)
                                appendNode("version", it.version)
                            }
                        }
                    }
                }
            }
        }
    }
}

artifactory {
    setContextUrl("http://artifactory.imulab.io/artifactory")
    publish(delegateClosureOf<PublisherConfig> {
        repository(delegateClosureOf<GroovyObject> {
            setProperty("repoKey", "gradle-dev-local")
            setProperty("username", "imulab")
            setProperty("password", "AKCp5btVPSh6Yg2HfkA7TtjnKGQuvN7SRtARiiXRD6BJicG26vSro7dQ2WNzGuX84LxMcaNVn")
            setProperty("maven", true)
        })
        defaults(delegateClosureOf<GroovyObject> {
            invokeMethod("publications", astrea)
        })
    })
    resolve(delegateClosureOf<ResolverConfig> {
        repository(delegateClosureOf<GroovyObject> {
            setProperty("repoKey", "gradle-dev")
            setProperty("username", "imulab")
            setProperty("password", "AKCp5btVPSh6Yg2HfkA7TtjnKGQuvN7SRtARiiXRD6BJicG26vSro7dQ2WNzGuX84LxMcaNVn")
            setProperty("maven", true)
        })
    })
}