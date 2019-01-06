# External Tools

# Android Extract
A hacked up version of the [FICS AT command extractor](https://github.com/FICS/atcmd/tree/master/extract), but instead of AT commands, it just extracts out Android file systems from various vendors (and keeps them available after doing so).
It also DOES NOT change any of the DAC/MAC/CAP permissions of the file systems to maintain their accuracy for BigMAC.

## Setup
You will need to download a massive collection of Android tools (tested to work on Ubuntu 16.04). [We have provided a binary download of all of these tools exactly as we have collected them (Mega Link)](https://mega.nz/file/Lgwz1DLB#GeG6YYbsykbOdonNyFFtqaC58quUzPDvQoBn1Al3J0g).
Unfortunately this means you must trust the binaries. We are working to dockerize this to allow for cross-distro extraction without any dependency hell. Apologies that there isn't a smoother setup currently available.
Next create a directory under this directory called `atsh_setup` and extract the downloaded files here (see the `DEPPATH` variable in android-extract.sh).

If you want to avoid extracting policies yourself and just try BigMAC, check out the `eval-policy.tar.gz` file available under the `eval/` directory at the root.
