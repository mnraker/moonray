// Copyright 2023-2024 DreamWorks Animation LLC
// SPDX-License-Identifier: Apache-2.0

//
#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <boost/stacktrace.hpp>
#else
#include <execinfo.h>  // backtrace
#include <sys/syscall.h>
#endif

#include "Util.h"

#include <tbb/mutex.h>

#include <cstring>

#if __cplusplus >= 201703L
#include <chrono>
#include <thread>
#endif

namespace moonray {
namespace mcrt_common {

void
threadSleep()
{
#if __cplusplus >= 201703L
    std::this_thread::sleep_for(std::chrono::microseconds(500));
#else
    usleep(500);
#endif
}

void
threadYield()
{
    __TBB_Yield();
}

void
debugPrintThreadID(const char *contextString)
{
    if (!contextString) contextString = "-- Thread ID = ";
#if __cplusplus >= 201703L
    std::thread::id tid = std::this_thread::get_id();
#else
    pid_t tid = syscall(SYS_gettid);
#endif

    // This printing is thread safe.
    std::printf("%s%d\n", contextString, tid);
    std::fflush(stdout);
}

void
debugPrintCallstack(const char *contextString)
{
    static tbb::mutex mutex;

    mutex.lock();

#if defined(_WIN32)

    std::printf("%s\n", boost::stacktrace::stacktrace());
    std::fflush(stdout);

#else

    if (!contextString) contextString = "-- Callstack:\n";
    std::printf("%s\n", contextString);

    const int MAX_BACKTRACE_SYMBOLS = 64;
    void *pointers[MAX_BACKTRACE_SYMBOLS];

    size_t size = backtrace(pointers, MAX_BACKTRACE_SYMBOLS);
    char **strings = backtrace_symbols(pointers, size);

    char indent[MAX_BACKTRACE_SYMBOLS + 1];
    memset(indent, ' ', sizeof(indent));

    int wrapperIndex = -1;

    // Iterate to size - 1 since final may not be null terminated.
    for(size_t i = 0; i < size - 1; ++i) {
        // Indent backtrace.
        indent[i - wrapperIndex - 1] = 0;
        char *p = strrchr(strings[i], '/');
        std::printf("%s%s\n", indent, p ? (p + 1) : strings[i]);
        indent[i - wrapperIndex - 1] = ' ';
    }

    std::printf("\n");
    std::fflush(stdout);

    free(strings);

#endif

    mutex.unlock();
}

// Functions exposed to ISPC:
extern "C"
{

void
CPP_debugPrintThreadID()
{
    debugPrintThreadID(nullptr);
}

void
CPP_debugPrintCallstack()
{
    debugPrintCallstack(nullptr);
}

}

} // namespace mcrt_common
} // namespace moonray

