NDK_TARGETVER=24
NDK_INCLUDES = -I/usr/lib/android-ndk/platforms/android-24/arch-arm64/usr/include
CFLAGS = -fPIE \
	 -Wall \
	 $(NDK_INCLUDES)

all: icaptool 

mtkutil: icaptool.c
	$(NDK_ROOT)/ndk-build NDK_APPLICATION_MK=`pwd`/Application.mk NDK_APP_OUT=. TARGET_PLATFORM=android-24

install: 
#	sudo adb shell 'su -c "mount -o rw,remount /system"'
	sudo adb shell 'su -mm -c magic_remount_rw'
	sudo adb push libs/arm64-v8a/mtkutil /sdcard/
	sudo adb shell 'su -c "cp /sdcard/mtkutil /system/bin/mtkutil"'
	sudo adb shell 'su -c "chmod +x /system/bin/mtkutil"'

reload:
	sudo adb shell 'su -c "echo 0 > /dev/wmtWifi"'
	sudo adb shell 'su -c "echo 1 > /dev/wmtWifi"'

run:
	sudo adb shell 'su -c "icaptool -i1"'
	sudo adb shell 'su -c "icaptool -i11"'
	sudo adb shell 'su -c "icaptool -i2"'
