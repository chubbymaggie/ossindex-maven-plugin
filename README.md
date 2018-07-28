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
