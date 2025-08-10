LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
#TARGET_ARCH := arm64
#TARGET_ARCH_ABI := arm64-v8a
LOCAL_MODULE := mtkutil
LOCAL_SRC_FILES := mtkutil.c
include $(BUILD_EXECUTABLE)
