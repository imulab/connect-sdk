plugins {
    java
    maven
    `maven-publish`
    id("org.jetbrains.kotlin.jvm").version("1.3.21")
    id("jacoco")
    id("com.jfrog.bintray").version("1.8.4")
}

group = "io.imulab"
version = "0.2.0-SNAPSHOT"

repositories {
    jcenter()
}

dependencies {
    implementation("org.jetbrains.kotlin:kotlin-stdlib-jdk8")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.2.0")
    api("org.bitbucket.b_c:jose4j:0.6.5")

    testImplementation("io.kotlintest:kotlintest-runner-junit5:3.3.2")
    testImplementation("com.nhaarman.mockitokotlin2:mockito-kotlin:2.1.0")
}

val sourceJar by tasks.registering(Jar::class) {
    classifier = "sources"
    from(sourceSets.main.get().allSource)
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

jacoco {
    toolVersion = "0.8.2"
}

publishing {
    publications {
        create<MavenPublication>("connect-sdk-publication") {
            from(components["java"])
            artifact(sourceJar.get())
            artifactId = "connect-sdk"
        }
    }
}

bintray {
    user = System.getenv("BINTRAY_USER")
    key = System.getenv("BINTRAY_API_KEY")
    setPublications("connect-sdk-publication")
    pkg = PackageConfig().apply {
        repo = "connect-sdk"
        name = "connect-sdk"
        userOrg = "imulab"
        vcsUrl = "https://github.com/imulab/connect-sdk.git"
        publicDownloadNumbers = true
        version = VersionConfig().apply {
            name = project.version.toString()
        }
        setLicenses("MIT")
    }
    publish = true
}
