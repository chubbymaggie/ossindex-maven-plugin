DEPRECATED, PLEASE UPGRADE TO ossindex-maven
==========================================================

* Homepage: https://sonatype.github.io/ossindex-maven/
* Sources: https://github.com/sonatype/ossindex-maven

The ossindex-maven-plugin has been deprecated in favour of ossindex-maven, which
should be available shortly. Currently version `1.0.0` is released, but it is being
re-versioned to `3.0.0` to avoid possible confusion related to this plugin.

This plugin will remain operational for now, however ossindex-maven uses
the new OSS Index "3.0" API, which has many benefits:

* Access to many more vulnerabilities. All the vulnerabilities in 2.x
  **AND MORE**
* 3.x database is being actively maintained, whereas the 2.x database
  is no longer maintained.
* The rewrite has cleaned up a bunch of old and crufty code, both in the
  backend and in the client.
* We will be shutting down the 2.x database sometime in the future.

There are also [OSS Index rules](https://sonatype.github.io/ossindex-maven/enforcer-rules/)
for [Maven Enforcer](https://maven.apache.org/enforcer/maven-enforcer-plugin/).

Upgrade path
------------

To disable the deprecation warning in 2.4.0, use the audit.hideDeprecationWarning option

```
mvn install net.ossindex:ossindex-maven-plugin:audit -Daudit.hideDeprecationWarning=true
```

See https://sonatype.github.io/ossindex-maven/maven-plugin/ for configuration information
for the ossindex-maven plugin. It can be configured directly within your POM file.

To run via the command line (which was described in this README for for 2.x)
you can do the following:

```
mvn org.sonatype.ossindex.maven:ossindex-maven-plugin:audit -f pom.xml
```

The various command line arguments which align with those of the deprecated version are:

* Prevent build from failing on vulnerability found: `-Dossindex.fail=[true|false]`
* Save results report: `-Dossindex.reportFile=file.[txt|json|xml]`
* Ignore a package: `-DexcludeCoordinates=<groupId>:<artifactId>[:<type>[:<classifier>]]:<version>`
* Ignore a vulnerability: `-Dossindex.excludeVulnerabilityIds=<vuln ID>`
* Scan specified scope: `-Dossindex.scope=<scope>`

