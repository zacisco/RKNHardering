import org.gradle.api.GradleException

plugins {
    alias(libs.plugins.android.application)
}

val appVersionName = resolveAppVersionName()
val appVersionCode = calculateAppVersionCode(appVersionName)

fun resolveAppVersionName(): String {
    val rawVersion = providers.gradleProperty("appVersionName").orElse("2.0").get().trim()
    val normalizedVersion = rawVersion.removePrefix("v")

    if (!Regex("""\d+\.\d+(\.\d+)?""").matches(normalizedVersion)) {
        throw GradleException("appVersionName must match X.Y or X.Y.Z, got '$rawVersion'")
    }

    return normalizedVersion
}

fun calculateAppVersionCode(versionName: String): Int {
    val parts = versionName.split(".")
    val major = parts[0].toInt()
    val minor = parts[1].toInt()
    val patch = parts.getOrElse(2) { "0" }.toInt()

    if (minor !in 0..99 || patch !in 0..99) {
        throw GradleException(
            "appVersionName supports only minor and patch values from 0 to 99, got '$versionName'"
        )
    }

    return (major * 10_000) + (minor * 100) + patch
}

android {
    namespace = "com.notcvnt.rknhardering"
    compileSdk {
        version = release(36) {
            minorApiLevel = 1
        }
    }

    defaultConfig {
        applicationId = "com.notcvnt.rknhardering"
        minSdk = 26
        targetSdk = 36
        versionCode = appVersionCode
        versionName = appVersionName

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        androidResources.localeFilters += listOf("en", "ru", "fa", "zh-rCN")
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    buildFeatures {
        buildConfig = true
    }
    testOptions {
        unitTests.isIncludeAndroidResources = true
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.material)
    implementation(libs.androidx.activity)
    implementation(libs.androidx.constraintlayout)
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(project(":xray-protos"))
    implementation(libs.grpc.okhttp)
    implementation(libs.okhttp)
    implementation(libs.okhttp.dnsoverhttps)
    testImplementation(libs.junit)
    testImplementation(libs.okhttp.mockwebserver)
    testImplementation("org.robolectric:robolectric:4.14.1")
    testImplementation("androidx.test:core:1.6.1")
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
}
