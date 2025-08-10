Tested with Realme 6i (RMX2040) running Android 11 using mt6769

# Build
* Export NDK (Ubuntu 18.04 in this case)
`export NDK_ROOT=/usr/lib/android-ndk/`
* Run make
`make`

## Optional: Docker
* see README.docker.md

# Install
* Needs a rooted device using Magisk
* `make install`

# Use
* Go into testmode, CIAP mode, and start capturing: `make run`
