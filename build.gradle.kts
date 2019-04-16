plugins {
    id("org.jetbrains.kotlin.jvm").version("1.3.21")
    id("jacoco")
}

repositories {
    jcenter()
}

jacoco {
    toolVersion = "0.8.2"
}

val test by tasks.getting(Test::class) {
    useJUnitPlatform()
}

val jacocoTestReport by tasks.getting(JacocoReport::class) {
    reports {
        html.apply {
            isEnabled = true
        }
        xml.apply {
            isEnabled = true
        }
        executionData(test)
    }
}

version = "0.1.0"

dependencies {
    implementation("org.jetbrains.kotlin:kotlin-stdlib-jdk8")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.2.0")
    implementation("org.bitbucket.b_c:jose4j:0.6.5")

    testImplementation("io.kotlintest:kotlintest-runner-junit5:3.3.2")
    testImplementation("com.nhaarman.mockitokotlin2:mockito-kotlin:2.1.0")
}
