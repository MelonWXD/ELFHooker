LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE    := inject
LOCAL_CPPFLAGS := -std=c++11
LOCAL_CFLAGS := -pie -fPIE
LOCAL_LDFLAGS := -pie -fPIE
LOCAL_LDLIBS := -llog
LOCAL_C_INCLUDES := $(LOCAL_PATH)
LOCAL_SRC_FILES := main.cpp      \
                   tracer.cpp    \
                   tools.cpp

include $(BUILD_EXECUTABLE)