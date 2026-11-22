# Security policy

eventhorizon sits between every app and the internet, so security reports are very welcome.

## Reporting a vulnerability

Please report privately through GitHub: open the **Security** tab of this repository and choose **Report a vulnerability**. Do not open a public issue for security problems.

Include what you found, how to reproduce it, and which version you ran (`eventhorizon -version`). You will get a reply within a week. Once a fix is released, you will be credited in the release notes unless you prefer not to be.

## Supported versions

Only the latest release gets security fixes.

## What counts

Examples of what is in scope:

* Making eventhorizon crash, hang or use unbounded memory with network input
* Answering clients it should not answer, or being usable for reflection or amplification with the default settings
* Reading or changing data through the API without access to it
* Bypassing a block in a way the rule order does not explain
* Weaknesses in DNS over TLS handling, such as certificate checks

Out of scope: blocklist contents (report those to the list's maintainers), and setups that disable the protections on purpose, such as `-allow-clients any` on a public address.

## Verifying downloads

Release archives carry signed build provenance. To check that a file was built by this repository's release workflow:

```sh
gh attestation verify eventhorizon_v0.1.0_linux_amd64.tar.gz --repo 0xAzathos/eventhorizon
```
