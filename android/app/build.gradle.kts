plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

fun prop(name: String): String = (project.findProperty(name) as String?) ?: ""

android {
    namespace = "in.guardianregistry.app"
    compileSdk = 35

    defaultConfig {
        applicationId = "in.guardianregistry.app"
        minSdk = 28            // StrongBox and modern Key Attestation
        targetSdk = 35
        versionCode = 1
        versionName = "0.24.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        buildConfigField("String", "FCM_PROJECT_ID", "\"${prop("grFcmProjectId")}\"")
        buildConfigField("String", "FCM_APP_ID", "\"${prop("grFcmAppId")}\"")
        buildConfigField("String", "FCM_API_KEY", "\"${prop("grFcmApiKey")}\"")
        buildConfigField("String", "FCM_SENDER_ID", "\"${prop("grFcmSenderId")}\"")
    }

    buildTypes {
        debug {
            buildConfigField("String", "API_BASE", "\"${prop("grApiBaseDebug")}\"")
            manifestPlaceholders["cleartext"] = "true"   // the emulator talks to a dev server on the host
        }
        release {
            buildConfigField("String", "API_BASE", "\"${prop("grApiBase")}\"")
            manifestPlaceholders["cleartext"] = "false"
            isMinifyEnabled = false
        }
    }
    buildFeatures { buildConfig = true }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
    lint { abortOnError = true; warningsAsErrors = false }
}

dependencies {
    implementation("com.google.firebase:firebase-messaging:24.1.0")
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20240303")
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
}
