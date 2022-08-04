package org.dependencytrack.parser.osv.model;

public enum Ecosystem {

    ANDROID("Android"),
    GSD("GSD"),
    GO("Go"),
    ERLANG("Hex"),
    JAVASCRIPT("JavaScript"),
    LINUX("Linux"),
    MAVEN("Maven"),
    NUGET("NuGet"),
    OSSFUZZ("OSS-Fuzz"),
    PACKAGIST("Packagist"),
    PYPI("PyPI"),
    RUBYGEMS("RubyGems"),
    UVI("UVI"),
    RUST("crates.io"),
    NPM("npm"),
    DWF("DWF"),
    DEBIAN("Debian"),
    DEBIAN_11("Debian:11"),
    DEBIAN_10("Debian:10"),
    DEBIAN_9("Debian:9"),
    DEBIAN_8("Debian:8"),
    DEBIAN_7("Debian:7"),
    DEBIAN_6("Debian:6.0"),
    DEBIAN_5("Debian:5.0"),
    DEBIAN_4("Debian:4.0"),
    DEBIAN_3_1("Debian:3.1"),
    DEBIAN_3_0("Debian:3.0"),
    GITHUB_ACTIONS("GitHub Actions");

    private final String value;

    Ecosystem(final String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
