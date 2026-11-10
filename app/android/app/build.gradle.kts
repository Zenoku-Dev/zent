plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.rivalafk.zentmail"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.rivalafk.zentmail"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            isShrinkResources = false
            signingConfig = signingConfigs.getByName("debug")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlin { jvmToolchain(17) }

    packaging { resources { excludes += listOf("/META-INF/{AL2.0,LGPL2.1}", "/META-INF/[^/]*/licenses/**") } }
}
