# Prerequisites
* install docker.io package

# Setup
* `docker build -t ndk .`

# Compiling
* `docker run -v "$PWD":/usr/src/myapp -w /usr/src/myapp --rm ndk:latest make`
