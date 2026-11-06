# Security policy

## Reporting a vulnerability in LookFirst

Please report it privately: open the repo's **Security** tab and choose **Report a vulnerability**. Don't open a public issue.

In scope: anything that makes LookFirst unsafe to run on a hostile file, such as writing to the disk, running or loading code from an archive, reaching the network, or crashing in a way an archive can trigger on purpose.

I'll reply within a few days, fix it on `main`, and credit you in the advisory if you'd like. Only the latest release is supported.

## Not a vulnerability

- **A file you opened was malicious**: follow [If it says "Don't open this"](../README.md#if-it-says-dont-open-this) in the README.
- **It missed something, or flagged something harmless**: open an issue with the matching template.
