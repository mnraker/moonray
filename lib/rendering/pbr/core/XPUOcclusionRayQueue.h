// Copyright 2023-2024 DreamWorks Animation LLC
// SPDX-License-Identifier: Apache-2.0

#pragma once
#include <moonray/rendering/pbr/Types.h>
#include <moonray/rendering/mcrt_common/Bundle.h>
#include <moonray/rendering/pbr/core/PbrTLState.h>
#include <moonray/rendering/rt/gpu/GPURay.h>
#include <moonray/rendering/rt/gpu/GPUAccelerator.h>

#include <scene_rdl2/scene/rdl2/VisibilityFlags.h>

// warning #1684: conversion from pointer to
// same-sized integral type (potential portability problem)
// needed for reinterpret_cast<intptr_t>(light)
#pragma warning push
#pragma warning disable 1684


namespace moonray {
namespace pbr {

/*
Dispatching rays to the GPU efficiently is a tricky problem.  You need to ensure
that your batch of rays is large enough to run efficiently to mitigate overhead,
and there are dozens of CPU threads that all want to submit small numbers of
individual rays to the GPU at once, creating contention.  It is not sufficient
to have one large shared queue that each CPU thread locks when it adds a few
rays because the other CPU threads will spend a lot of time waiting.

You also need to keep the GPU as busy as possible but not cause the CPU side to
stall by giving the GPU more work than it can process.

MoonRay currently implements a fairly simple scheme that also works reasonably well,
if a bit memory inefficient.  Each CPU thread has its own large queue of occlusion
rays to process (65536 rays).  Each ray is 128 bytes, so each thread's queue is 8MB.
This is not ideal, but the cost scales with the number of threads.  I.e. a 96-thread
render will consume 768MB of memory for XPU queues.  BUT, these systems have 192GB of RAM
so this is not a major problem.

Since each CPU thread has its own queue for XPU rays, there is no contention when filling
the queues.  Previous work used a single shared queue, but the overhead of 96 threads contending
for a lock on the queue was too high and performance was poor.

When a CPU thread has completely filled its queue, it attempts to call the GPU to process
those queued rays.  First, it checks how many other CPU threads are waiting for the GPU.  
If there are more than two other threads waiting, this CPU thread will process its rays by 
itself.  This is a simple automatic load-balancing scheme that ensures that the CPU side isn't 
too blocked with too many CPU threads waiting for the GPU.  It also keeps the GPU fed with 
a constant uninterrupted stream of work by having a few threads queued up waiting with work ready.

This system can potentially be improved upon with Keith's lock-free queue ideas, 
but this current scheme is a reasonable baseline that we can compare more sophisticated
and efficient methods.

The API design of this queue class resembles the other queues in mcrt_common/Bundle.h.
The two main methods are addEntries() and flush().
*/

class XPUOcclusionRayQueue
{
public:
    // The CPU handler that is called when the GPU is busy
    typedef void (*CPUHandler)(mcrt_common::ThreadLocalState *tls,
                               unsigned numEntries,
                               BundledOcclRay **entryData,
                               void *userData);

    // The GPU handler that calls the GPU
    typedef void (*GPUHandler)(mcrt_common::ThreadLocalState *tls,
                               unsigned numEntries,
                               BundledOcclRay *entryData,
                               const rt::GPURay *gpuRays,
                               std::atomic<int>& threadsUsingGPU);

    XPUOcclusionRayQueue(unsigned numCPUThreads,
                         unsigned cpuThreadQueueSize,
                         const rt::GPUAccelerator* gpuAccel,
                         CPUHandler cpuThreadQueueHandler,
                         GPUHandler gpuQueueHandler,
                         void *handlerData) :
        mNumCPUThreads(numCPUThreads),
        mCPUThreadQueueSize(cpuThreadQueueSize),
        mCPUThreadQueueHandler(cpuThreadQueueHandler),
        mGPUQueueHandler(gpuQueueHandler),
        mHandlerData(handlerData)
    {
        MNRY_ASSERT(numCPUThreads);
        MNRY_ASSERT(cpuThreadQueueSize);
        MNRY_ASSERT(mCPUThreadQueueHandler);
        MNRY_ASSERT(mGPUQueueHandler);

        // Create a queue for each CPU thread
        mCPUThreadQueueEntries.resize(mNumCPUThreads);
        mCPUThreadQueueNumQueued.resize(mNumCPUThreads);

        for (size_t i = 0; i < numCPUThreads; i++) {
#ifdef __APPLE__
            // The GPU accelerator supports UMA: we ask for a UMA buffer from the accelerator instead
            //  of allocating one ourselves.
            mCPUThreadQueueEntries[i] = (BundledOcclRay*)gpuAccel->getBundledOcclRaysBufUMA(
                                            i, mCPUThreadQueueSize, sizeof(BundledOcclRay));
#else
            mCPUThreadQueueEntries[i] = scene_rdl2::util::alignedMallocArray<BundledOcclRay>(mCPUThreadQueueSize, CACHE_LINE_SIZE);
#endif
            mCPUThreadQueueNumQueued[i] = 0;
        }

        mNumThreadsUsingGPU = 0;
    }

    virtual ~XPUOcclusionRayQueue()
    {
        for (size_t i = 0; i < mNumCPUThreads; i++) {
            MNRY_ASSERT(mCPUThreadQueueNumQueued[i] == 0);
#ifdef __APPLE__
            // Nothing to do - the GPUAccelerator will destroy the UMA buffer
#else
            scene_rdl2::util::alignedFree(mCPUThreadQueueEntries[i]);
#endif
        }
    }

    unsigned getMemoryUsed() const
    {
        return (sizeof(BundledOcclRay) * mCPUThreadQueueSize * mNumCPUThreads) + sizeof(*this);
    }

    bool isValid() const
    {
        MNRY_ASSERT(mGPUQueueHandler);
        return true;
    }

    // The CPU threads call this function to queue up rays (entries.)
    void addEntries(mcrt_common::ThreadLocalState *tls,
                    unsigned numEntries,
                    BundledOcclRay *entries)
    {
        MNRY_ASSERT(tls);
        MNRY_ASSERT(numEntries);
        MNRY_ASSERT(entries);

        EXCL_ACCUMULATOR_PROFILE(tls, EXCL_ACCUM_QUEUE_LOGIC);

        while (numEntries >= mCPUThreadQueueSize) {
            // The number of rays that have been submitted exceeds or equals the
            // CPU thread queue size.  Process them in batches of mCPUThreadQueueSize.
            processRays(tls, mCPUThreadQueueSize, entries);
            entries += mCPUThreadQueueSize;
            numEntries -= mCPUThreadQueueSize;
        }

        int threadIdx = tls->mThreadIdx;

        MNRY_ASSERT(mCPUThreadQueueNumQueued[threadIdx] <= mCPUThreadQueueSize);
        unsigned totalEntries = mCPUThreadQueueNumQueued[threadIdx] + numEntries;

        // Is there enough room in the CPU thread queue for the new entries?
        if (totalEntries <= mCPUThreadQueueSize) {
            // Copy entries into CPU thread's queue as there is room for them in that queue.
            memcpy(mCPUThreadQueueEntries[threadIdx] + mCPUThreadQueueNumQueued[threadIdx],
                   entries,
                   numEntries * sizeof(BundledOcclRay));
            mCPUThreadQueueNumQueued[threadIdx] = totalEntries;
            return;
        }

        // Else there isn't enough room in the CPU thread's queue for all of the new
        // entries.  We need to flush the queue to free up space.
        processRays(tls, mCPUThreadQueueNumQueued[threadIdx], mCPUThreadQueueEntries[threadIdx]);
        mCPUThreadQueueNumQueued[threadIdx] = 0;

        // Now that the queue is empty, we can add the new entries.
        memcpy(mCPUThreadQueueEntries[threadIdx],
               entries,
               numEntries * sizeof(BundledOcclRay));
        mCPUThreadQueueNumQueued[threadIdx] = numEntries;

        MNRY_ASSERT(mCPUThreadQueueNumQueued[threadIdx] <= mCPUThreadQueueSize);
    }

    // Explicit flush of the CPU queues per thread.
    unsigned flush(mcrt_common::ThreadLocalState *tls, scene_rdl2::alloc::Arena *arena)
    {
        EXCL_ACCUMULATOR_PROFILE(tls, EXCL_ACCUM_QUEUE_LOGIC);

        int threadIdx = tls->mThreadIdx;

        int numFlushed = mCPUThreadQueueNumQueued[threadIdx];
        if (mCPUThreadQueueNumQueued[threadIdx]) {
            processRays(tls, mCPUThreadQueueNumQueued[threadIdx], mCPUThreadQueueEntries[threadIdx]);
            mCPUThreadQueueNumQueued[threadIdx] = 0;
        }

        return numFlushed;
    }

    void reset()
    {
        for (size_t i = 0; i < mNumCPUThreads; i++) {
            mCPUThreadQueueNumQueued[i] = 0;
        }
    }

protected:

    void processRays(mcrt_common::ThreadLocalState *tls,
                     unsigned numRays,
                     BundledOcclRay *rays)
    {
        EXCL_ACCUMULATOR_PROFILE(tls, EXCL_ACCUM_QUEUE_LOGIC);

        MNRY_ASSERT(numRays);

#ifdef __APPLE__
        constexpr int maxThreads = 64;
#else
        // Epirically-determined maximum number of threads that can be waiting on the GPU.
        // Might want to make this configurable.
        constexpr int maxThreads = 5;
#endif

        if ((mNumThreadsUsingGPU.load() < maxThreads) && numRays > 1024) {
            // There are an acceptable number of threads using the GPU, so we
            // can go ahead.

            pbr::TLState *pbrTls = tls->mPbrTls.get();
            scene_rdl2::alloc::Arena *arena = &tls->mArena;

            const FrameState &fs = *pbrTls->mFs;
            rt::GPUAccelerator *accel = const_cast<rt::GPUAccelerator*>(fs.mGPUAccel);

#ifdef __APPLE__
            rt::GPURay* gpuRays = accel->getGPURaysBufUMA(pbrTls->mThreadIdx);

            for (size_t i = 0; i < numRays; ++i) {
                const BundledOcclRay &occlRay = rays[i];
                MNRY_ASSERT(occlRay.isValid());
                // Apple uses UMA so it gets most of the data for the GPURay directly from
                // the queued BundledOcclRays that are in UMA memory.  Thus, the GPURay only
                // has a few members that aren't present on the BundledOcclRay.
                gpuRays[i].mShadowReceiverId = occlRay.mShadowReceiverId;
                const scene_rdl2::rdl2::Light* light = static_cast<BundledOcclRayData *>(
                    pbrTls->getListItem(occlRay.mDataPtrHandle, 0))->mLight->getRdlLight();
                gpuRays[i].mLightId = reinterpret_cast<intptr_t>(light);
            }
#else
            rt::GPURay* gpuRays = arena->allocArray<rt::GPURay>(numRays, CACHE_LINE_SIZE);

            for (size_t i = 0; i < numRays; ++i) {
                const BundledOcclRay &occlRay = rays[i];
                MNRY_ASSERT(occlRay.isValid());
                // Optix doesn't access these values from the cpu ray directly, so we copy the
                // values here into a GPU-accessible buffer
                gpuRays[i].mOriginX = occlRay.mOrigin.x;
                gpuRays[i].mOriginY = occlRay.mOrigin.y;
                gpuRays[i].mOriginZ = occlRay.mOrigin.z;
                gpuRays[i].mDirX = occlRay.mDir.x;
                gpuRays[i].mDirY = occlRay.mDir.y;
                gpuRays[i].mDirZ = occlRay.mDir.z;
                gpuRays[i].mMinT = occlRay.mMinT;
                gpuRays[i].mMaxT = occlRay.mMaxT;
                gpuRays[i].mTime = occlRay.mTime;
                gpuRays[i].mMask = scene_rdl2::rdl2::SHADOW;
                gpuRays[i].mShadowReceiverId = occlRay.mShadowReceiverId;
                const scene_rdl2::rdl2::Light* light = static_cast<BundledOcclRayData *>(
                    pbrTls->getListItem(occlRay.mDataPtrHandle, 0))->mLight->getRdlLight();
                gpuRays[i].mLightId = reinterpret_cast<intptr_t>(light);
            }
#endif

            ++tls->mHandlerStackDepth;
            (*mGPUQueueHandler)(tls,
                                numRays,
                                rays,
                                gpuRays,
                                mNumThreadsUsingGPU);
            MNRY_ASSERT(tls->mHandlerStackDepth > 0);
            --tls->mHandlerStackDepth;

        } else {
            // There's too many threads using the GPU, and we would need to wait
            // too long.  Process these rays on the CPU instead.

            // We need an array of pointers to entries, not of the entries themselves.
            scene_rdl2::alloc::Arena *arena = &tls->mArena;
            SCOPED_MEM(arena);
            BundledOcclRay** entries = arena->allocArray<BundledOcclRay*>(numRays, CACHE_LINE_SIZE);
            for (int i = 0; i < numRays; i++) {
                entries[i] = const_cast<BundledOcclRay*>(rays + i);
            }

            ++tls->mHandlerStackDepth;
            (*mCPUThreadQueueHandler)(tls, numRays, entries, mHandlerData);
            MNRY_ASSERT(tls->mHandlerStackDepth > 0);
            --tls->mHandlerStackDepth;
        }
    }

    unsigned                     mNumCPUThreads;
    unsigned                     mCPUThreadQueueSize;
    std::vector<BundledOcclRay*> mCPUThreadQueueEntries;
    std::vector<unsigned>        mCPUThreadQueueNumQueued;
    CPUHandler                   mCPUThreadQueueHandler;
    std::atomic<int>             mNumThreadsUsingGPU;
    GPUHandler                   mGPUQueueHandler;
    void *                       mHandlerData;
};

} // namespace pbr
} // namespace moonray
