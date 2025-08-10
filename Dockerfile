FROM ubuntu:18.04

RUN apt-get -y update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y google-android-ndk-installer file
ENV NDK_ROOT=/usr/lib/android-ndk/

COPY . /usr/src/myapp
WORKDIR /usr/src/myapp
