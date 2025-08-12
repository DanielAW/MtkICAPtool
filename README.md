Tested on Realme 6i (RMX2040) running Android 11 using mt6769. Parts taken from the Mediatek "wifitesttool".

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
* setup TCP forwarding over ADB: `sudo adb forward tcp:9090 tcp:9090`
* Go into testmode, CIAP mode, and start capturing: `make run`
* Use a second terminal to run the spectrum plot: `python plot_spectrum_tcp.py`
* Use `make stop` to send the stop command
