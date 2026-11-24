plugins {
    `java-library`
}

group = "guardianregistry"
version = "0.26.0"

java {
    toolchain { languageVersion.set(JavaLanguageVersion.of(17)) }
}

repositories { mavenCentral() }

dependencies {
    implementation("org.json:json:20240303")
    testImplementation(platform("org.junit:junit-bom:5.11.3"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.test {
    useJUnitPlatform()
    // The live test runs only when CI points it at a running registry (see LiveRegistryTest).
    listOf("GR_LIVE_URL", "GR_LIVE_API_KEY", "GR_LIVE_MOBILE", "GR_LIVE_GUARDIAN_TOKEN").forEach { k ->
        System.getenv(k)?.let { environment(k, it) }
    }
    testLogging { events("passed", "skipped", "failed"); showStandardStreams = true }
}
