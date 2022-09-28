// Copyright 2011 Boris Kogan (boris@thekogans.net)
//
// This file is part of libthekogans_stream.
//
// libthekogans_stream is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// libthekogans_stream is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with libthekogans_stream. If not, see <http://www.gnu.org/licenses/>.

#include "thekogans/util/Environment.h"
#if defined (TOOLCHAIN_OS_Windows)
    #if !defined (_WINDOWS_)
        #if !defined (WIN32_LEAN_AND_MEAN)
            #define WIN32_LEAN_AND_MEAN
        #endif // !defined (WIN32_LEAN_AND_MEAN)
        #if !defined (NOMINMAX)
            #define NOMINMAX
        #endif // !defined (NOMINMAX)
        #include <windows.h>
    #endif // !defined (_WINDOWS_)
#elif defined (TOOLCHAIN_OS_Linux)
    #include <sys/epoll.h>
#elif defined (TOOLCHAIN_OS_OSX)
    #include <sys/types.h>
    #include <sys/event.h>
    #include <sys/time.h>
    #include <cassert>
#endif // defined (TOOLCHAIN_OS_Windows)
#include <vector>
#include "thekogans/util/Flags.h"
#include "thekogans/util/Exception.h"
#include "thekogans/util/LoggerMgr.h"
#if defined (TOOLCHAIN_OS_Windows)
    #include "thekogans/util/StringUtils.h"
#endif // defined (TOOLCHAIN_OS_Windows)
#include "thekogans/stream/AsyncIoEventSink.h"
#if defined (TOOLCHAIN_OS_Linux)
    #include "thekogans/stream/Socket.h"
#endif // defined (TOOLCHAIN_OS_Linux)
#include "thekogans/stream/AsyncIoEventQueue.h"

namespace thekogans {
    namespace stream {

        struct AsyncIoEventQueue::StreamDeleter :
                public AsyncIoEventQueueRegistryList::Callback {
        private:
            AsyncIoEventQueue &eventQueue;

        public:
            explicit StreamDeleter (AsyncIoEventQueue &eventQueue_) :
                eventQueue (eventQueue_) {}
            virtual ~StreamDeleter () {
                eventQueue.ReleaseDeletedStreams ();
            }

            // AsyncIoEventQueueRegistryList::Callback
            virtual bool operator () (Stream *stream) {
                eventQueue.DeleteStream (*stream);
                return true;
            }
        };

    #if defined (TOOLCHAIN_OS_Windows)
        AsyncIoEventQueue::AsyncIoEventQueue (util::ui32 concurrentThreads) :
                handle (
                    CreateIoCompletionPort (
                        THEKOGANS_UTIL_INVALID_HANDLE_VALUE,
                        0, 0, concurrentThreads)) {
    #elif defined (TOOLCHAIN_OS_Linux)
        AsyncIoEventQueue::AsyncIoEventQueue (util::ui32 maxSize) :
                handle (epoll_create (maxSize)) {
    #elif defined (TOOLCHAIN_OS_OSX)
        AsyncIoEventQueue::AsyncIoEventQueue () :
                handle (kqueue ()) {
    #endif // defined (TOOLCHAIN_OS_Windows)
            if (handle == THEKOGANS_UTIL_INVALID_HANDLE_VALUE) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE);
            }
        #if defined (TOOLCHAIN_OS_Linux) || defined (TOOLCHAIN_OS_OSX)
            Pipe::Create (readPipe, writePipe);
            if (!readPipe.IsOpen () || !writePipe.IsOpen ()) {
                 THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE);
            }
            readPipe.SetBlocking (false);
            // NOTE: By making the write pipe async we guard against
            // a pathological case where a client calls Break enough
            // times to block forever. This combined with correct
            // error handling in Break (below) guarantees that it
            // should not be a problem.
            writePipe.SetBlocking (false);
        #if defined (TOOLCHAIN_OS_Linux)
            epoll_event event;
            event.events = EPOLLIN;
            event.data.u64 = StreamRegistry::INVALID_TOKEN;
            if (epoll_ctl (handle, EPOLL_CTL_ADD, readPipe.handle, &event) < 0) {
        #else // defined (TOOLCHAIN_OS_Linux)
            keventStruct event;
            keventSet (&event, readPipe.handle, EVFILT_READ, EV_ADD, 0, 0, StreamRegistry::INVALID_TOKEN);
            if (keventFunc (handle, &event, 1, 0, 0, 0) < 0) {
        #endif // defined (TOOLCHAIN_OS_Linux)
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE);
            }
        #endif // defined (TOOLCHAIN_OS_Linux) || defined (TOOLCHAIN_OS_OSX)
        }

        AsyncIoEventQueue::~AsyncIoEventQueue () {
        #if defined (TOOLCHAIN_OS_Linux) || defined (TOOLCHAIN_OS_OSX)
            THEKOGANS_UTIL_TRY {
                readPipe.Close ();
                writePipe.Close ();
            }
            THEKOGANS_UTIL_CATCH_AND_LOG_SUBSYSTEM (THEKOGANS_STREAM)
        #endif // defined (TOOLCHAIN_OS_Linux) || defined (TOOLCHAIN_OS_OSX)
            THEKOGANS_UTIL_TRY {
                StreamDeleter streamDeleter (*this);
                registryList.for_each (streamDeleter);
            #if defined (TOOLCHAIN_OS_Windows)
                WaitForEvents (DEFAULT_MAX_EVENTS_BATCH, util::TimeSpec::Zero);
            #endif // defined (TOOLCHAIN_OS_Windows)
            }
            THEKOGANS_UTIL_CATCH_AND_LOG_SUBSYSTEM (THEKOGANS_STREAM)
        #if defined (TOOLCHAIN_OS_Windows)
            CloseHandle (handle);
        #elif defined (TOOLCHAIN_OS_Linux)
            close (handle);
        #elif defined (TOOLCHAIN_OS_OSX)
            close (handle);
        #endif // defined (TOOLCHAIN_OS_Windows)
        }

        void AsyncIoEventQueue::AddStream (
                Stream &stream,
                AsyncIoEventSink &eventSink,
                std::size_t bufferLength) {
            if (stream.IsOpen () && !stream.IsAsync ()) {
                // Adding the same stream to the queue is stupid but harmless.
                if (!registryList.contains (&stream)) {
                #if defined (TOOLCHAIN_OS_Windows)
                    if (CreateIoCompletionPort (
                            stream.handle, handle, (ULONG_PTR)&stream, 0) == 0) {
                        THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                            THEKOGANS_UTIL_OS_ERROR_CODE);
                    }
                #endif // defined (TOOLCHAIN_OS_Windows)
                    {
                        util::LockGuard<util::SpinLock> guard (spinLock);
                        registryList.push_back (&stream);
                    }
                    stream.AddRef ();
                    stream.asyncInfo.Reset (
                        new Stream::AsyncInfo (*this, stream, eventSink, bufferLength));
                    stream.InitAsyncIo ();
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        void AsyncIoEventQueue::DeleteStream (Stream &stream) {
            if (stream.IsAsync () && &stream.asyncInfo->eventQueue == this) {
                // This is safe as contains operates on the node and
                // not the list.
                // NOTE: This check alows you to call DeleteStream
                // multiple times with all but the first time being
                // a noop.
                if (registryList.contains (&stream)) {
                #if defined (TOOLCHAIN_OS_Windows)
                    CancelIoEx (stream.handle, 0);
                #else // defined (TOOLCHAIN_OS_Windows)
                    DeleteStreamForEvents (stream, stream.asyncInfo->events);
                #endif // defined (TOOLCHAIN_OS_Windows)
                    {
                        util::LockGuard<util::SpinLock> guard (spinLock);
                        registryList.erase (&stream);
                        deletedStreamsList.push_back (&stream);
                    }
                    stream.asyncInfo->ReleaseResources ();
                    stream.TerminateAsyncIo ();
                    // Kick WaitForEvents to get it to clean up the mess.
                    Break ();
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

    #if defined (TOOLCHAIN_OS_Windows)
        namespace {
            #define STATUS_CANCELED 0xC0000120
            #define STATUS_LOCAL_DISCONNECT 0xC000013B
            #define STATUS_REMOTE_DISCONNECT 0xC000013C
            #define STATUS_PIPE_BROKEN 0xC000014b
            #define STATUS_CONNECTION_RESET 0xC000020D

            std::string ErrorCodeTostring (THEKOGANS_UTIL_ERROR_CODE errorCode) {
                return
                    errorCode == STATUS_CANCELED ? "STATUS_CANCELED" :
                    errorCode == STATUS_LOCAL_DISCONNECT ? "STATUS_LOCAL_DISCONNECT" :
                    errorCode == STATUS_REMOTE_DISCONNECT ? "STATUS_REMOTE_DISCONNECT" :
                    errorCode == STATUS_PIPE_BROKEN ? "STATUS_PIPE_BROKEN" :
                    errorCode == STATUS_CONNECTION_RESET ? "STATUS_CONNECTION_RESET" :
                    util::FormatString ("Unknown code: %x", errorCode);
            }
        }
    #endif // defined (TOOLCHAIN_OS_Windows)

        void AsyncIoEventQueue::WaitForEvents (
                std::size_t maxEventsBatch,
                util::TimeSpec timeSpec) {
            if (maxEventsBatch > 0) {
                volatile StreamDeleter streamDeleter (*this);
            #if defined (TOOLCHAIN_OS_Windows)
                std::vector<OVERLAPPED_ENTRY> iocpEvents (maxEventsBatch);
                ULONG count = 0;
                if (!GetQueuedCompletionStatusEx (handle, iocpEvents.data (),
                        (ULONG)maxEventsBatch, &count, (DWORD)timeSpec.ToMilliseconds (), FALSE)) {
                    THEKOGANS_UTIL_ERROR_CODE errorCode = THEKOGANS_UTIL_OS_ERROR_CODE;
                    if (errorCode != WAIT_TIMEOUT) {
                        THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (errorCode);
                    }
                }
                else {
                    for (ULONG i = 0; i < count; ++i) {
                        if (iocpEvents[i].lpOverlapped != 0) {
                            Stream::AsyncInfo::Overlapped::SharedPtr overlapped (
                                (Stream::AsyncInfo::Overlapped *)iocpEvents[i].lpOverlapped, false);
                            assert ((Stream *)iocpEvents[i].lpCompletionKey == overlapped->stream.Get ());
                            overlapped->Prolog ();
                            THEKOGANS_UTIL_ERROR_CODE errorCode = overlapped->GetError ();
                            if (errorCode != ERROR_SUCCESS) {
                                // This check is very important as it will be returned
                                // on all outstanding io when CancelIoEx () has been called.
                                // That happens in DeleteStream () and in all likelihood
                                // the stream is gone. So, if we see STATUS_CANCELED, we
                                // silently ignore it.
                                if (errorCode != STATUS_CANCELED) {
                                    if (errorCode == STATUS_LOCAL_DISCONNECT ||
                                            errorCode == STATUS_REMOTE_DISCONNECT ||
                                            errorCode == STATUS_PIPE_BROKEN ||
                                            errorCode == STATUS_CONNECTION_RESET) {
                                        THEKOGANS_UTIL_LOG_SUBSYSTEM_DEBUG (
                                            THEKOGANS_STREAM,
                                            "errorCode: %s.\n",
                                            ErrorCodeTostring (errorCode).c_str ());
                                        overlapped->event = Stream::AsyncInfo::EventDisconnect;
                                        overlapped->stream->HandleOverlapped (*overlapped);
                                    }
                                    else {
                                        overlapped->stream->HandleError (
                                            THEKOGANS_UTIL_ERROR_CODE_EXCEPTION (errorCode));
                                    }
                                }
                            }
                            else {
                                overlapped->Epilog ();
                                overlapped->stream->HandleOverlapped (*overlapped);
                            }
                        }
                    }
                }
            #elif defined (TOOLCHAIN_OS_Linux)
                std::vector<epoll_event> epollEvents (maxEventsBatch);
                int count = epoll_wait (handle, epollEvents.data (), maxEventsBatch,
                    timeSpec == util::TimeSpec::Infinite ? -1 : timeSpec.ToMilliseconds ());
                if (count < 0) {
                    THEKOGANS_UTIL_ERROR_CODE errorCode = THEKOGANS_UTIL_OS_ERROR_CODE;
                    // EINTR means a signal interrupted our wait. Quietly
                    // return so that the AsyncIoEventQueue owner can call
                    // WaitForEvents again.
                    if (errorCode != EINTR) {
                        THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (errorCode);
                    }
                }
                else {
                    for (int i = 0; i < count; ++i) {
                        if (epollEvents[i].data.u64 == StreamRegistry::INVALID_TOKEN) {
                            std::size_t bufferSize = readPipe.GetDataAvailable ();
                            if (bufferSize != 0) {
                                std::vector<util::ui8> buffer (bufferSize);
                                readPipe.Read (buffer.data (), bufferSize);
                            }
                        }
                        else {
                            Stream::SharedPtr stream = StreamRegistry::Instance ().Get (epollEvents[i].data.u64);
                            if (stream.Get () != 0 && registryList.contains (stream.Get ())) {
                                if (epollEvents[i].events & EPOLLERR) {
                                    // For all the great things epoll does, it's error
                                    // handling is fucking abysmal. Not returning the
                                    // error code with EPOLLERR just does not make any
                                    // sense. For sockets, we have a way of getting
                                    // error codes. For pipes we do not. Since correct
                                    // processing of EPOLLERR is to close the stream,
                                    // it's not completely hopeless. It would just be
                                    // really nice if we could show something meaningful
                                    // in the log.
                                    Socket::SharedPtr socket = util::dynamic_refcounted_sharedptr_cast<Socket> (stream);
                                    if (socket.Get () != 0) {
                                        THEKOGANS_UTIL_ERROR_CODE errorCode = socket->GetErrorCode ();
                                        if (errorCode == EPIPE) {
                                            socket->HandleAsyncEvent (Stream::AsyncInfo::EventDisconnect);
                                        }
                                        else {
                                            socket->HandleError (
                                                THEKOGANS_UTIL_ERROR_CODE_EXCEPTION (errorCode));
                                        }
                                    }
                                    else {
                                        stream->HandleError (
                                            THEKOGANS_UTIL_STRING_EXCEPTION (
                                                "%s", "Unknown stream error."));
                                    }
                                }
                                else {
                                    if (epollEvents[i].events & EPOLLIN) {
                                        util::ui32 event =
                                            util::Flags32 (stream->asyncInfo->events).Test (
                                                Stream::AsyncInfo::EventRead) ? Stream::AsyncInfo::EventRead :
                                            util::Flags32 (stream->asyncInfo->events).Test (
                                                Stream::AsyncInfo::EventReadFrom) ? Stream::AsyncInfo::EventReadFrom :
                                            util::Flags32 (stream->asyncInfo->events).Test (
                                                Stream::AsyncInfo::EventReadMsg) ? Stream::AsyncInfo::EventReadMsg :
                                            Stream::AsyncInfo::EventInvalid;
                                        if (event != Stream::AsyncInfo::EventInvalid) {
                                            stream->HandleAsyncEvent (event);
                                        }
                                    }
                                    if (epollEvents[i].events & EPOLLOUT) {
                                        util::ui32 event =
                                            util::Flags32 (stream->asyncInfo->events).Test (
                                                Stream::AsyncInfo::EventConnect) ? Stream::AsyncInfo::EventConnect :
                                            util::Flags32 (stream->asyncInfo->events).Test (
                                                Stream::AsyncInfo::EventShutdown) ? Stream::AsyncInfo::EventShutdown :
                                            util::Flags32 (stream->asyncInfo->events).Test (
                                                Stream::AsyncInfo::EventWrite) ? Stream::AsyncInfo::EventWrite :
                                            util::Flags32 (stream->asyncInfo->events).Test (
                                                Stream::AsyncInfo::EventWriteTo) ? Stream::AsyncInfo::EventWriteTo :
                                            util::Flags32 (stream->asyncInfo->events).Test (
                                                Stream::AsyncInfo::EventWriteMsg) ? Stream::AsyncInfo::EventWriteMsg :
                                            Stream::AsyncInfo::EventInvalid;
                                        if (event != Stream::AsyncInfo::EventInvalid) {
                                            stream->HandleAsyncEvent (event);
                                        }
                                    }
                                    if ((epollEvents[i].events & EPOLLRDHUP) || (epollEvents[i].events & EPOLLHUP)) {
                                        stream->HandleAsyncEvent (Stream::AsyncInfo::EventDisconnect);
                                    }
                                }
                            }
                        }
                    }
                }
            #elif defined (TOOLCHAIN_OS_OSX)
                timespec timespec = timeSpec.Totimespec ();
                std::vector<keventStruct> kqueueEvents (maxEventsBatch);
                int count = keventFunc (handle, 0, 0, kqueueEvents.data (), maxEventsBatch,
                    timeSpec == util::TimeSpec::Infinite ? 0 : &timespec);
                if (count < 0) {
                    THEKOGANS_UTIL_ERROR_CODE errorCode = THEKOGANS_UTIL_OS_ERROR_CODE;
                    // EINTR means a signal interrupted our wait. Quietly
                    // return so that the AsyncIoEventQueue owner can call
                    // WaitForEvents again.
                    if (errorCode != EINTR) {
                        THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (errorCode);
                    }
                }
                else {
                    for (int i = 0; i < count; ++i) {
                        if (kqueueEvents[i].udata == StreamRegistry::INVALID_TOKEN) {
                            std::size_t bufferSize = readPipe.GetDataAvailable ();
                            if (bufferSize != 0) {
                                std::vector<util::ui8> buffer (bufferSize);
                                readPipe.Read (buffer.data (), bufferSize);
                            }
                        }
                        else {
                            Stream::SharedPtr stream = StreamRegistry::Instance ().Get (kqueueEvents[i].udata);
                            if (stream.Get () != 0 && registryList.contains (stream.Get ())) {
                                if (kqueueEvents[i].flags & EV_ERROR) {
                                    stream->HandleError (
                                        THEKOGANS_UTIL_ERROR_CODE_EXCEPTION (
                                            (THEKOGANS_UTIL_ERROR_CODE)kqueueEvents[i].data));
                                }
                                else if (kqueueEvents[i].flags & EV_EOF) {
                                    // If no one is listening on the other side, kqueue returns
                                    // EV_EOF instead of ECONNREFUSED. Simulate an error that would
                                    // be returned if we did a blocking connect.
                                    if (util::Flags32 (stream->asyncInfo->events).Test (
                                            Stream::AsyncInfo::EventConnect)) {
                                        stream->HandleError (
                                            THEKOGANS_UTIL_ERROR_CODE_EXCEPTION (ECONNREFUSED));
                                    }
                                    else {
                                        stream->HandleAsyncEvent (Stream::AsyncInfo::EventDisconnect);
                                    }
                                }
                                else if (kqueueEvents[i].filter == EVFILT_READ) {
                                    util::ui32 event =
                                        util::Flags32 (stream->asyncInfo->events).Test (
                                            Stream::AsyncInfo::EventRead) ? Stream::AsyncInfo::EventRead :
                                        util::Flags32 (stream->asyncInfo->events).Test (
                                            Stream::AsyncInfo::EventReadFrom) ? Stream::AsyncInfo::EventReadFrom :
                                        util::Flags32 (stream->asyncInfo->events).Test (
                                            Stream::AsyncInfo::EventReadMsg) ? Stream::AsyncInfo::EventReadMsg :
                                        Stream::AsyncInfo::EventInvalid;
                                    if (event != Stream::AsyncInfo::EventInvalid) {
                                        stream->HandleAsyncEvent (event);
                                    }
                                }
                                else if (kqueueEvents[i].filter == EVFILT_WRITE) {
                                    util::ui32 event =
                                        util::Flags32 (stream->asyncInfo->events).Test (
                                            Stream::AsyncInfo::EventConnect) ? Stream::AsyncInfo::EventConnect :
                                        util::Flags32 (stream->asyncInfo->events).Test (
                                            Stream::AsyncInfo::EventShutdown) ? Stream::AsyncInfo::EventShutdown :
                                        util::Flags32 (stream->asyncInfo->events).Test (
                                            Stream::AsyncInfo::EventWrite) ? Stream::AsyncInfo::EventWrite :
                                        util::Flags32 (stream->asyncInfo->events).Test (
                                            Stream::AsyncInfo::EventWriteTo) ? Stream::AsyncInfo::EventWriteTo :
                                        util::Flags32 (stream->asyncInfo->events).Test (
                                            Stream::AsyncInfo::EventWriteMsg) ? Stream::AsyncInfo::EventWriteMsg :
                                        Stream::AsyncInfo::EventInvalid;
                                    if (event != Stream::AsyncInfo::EventInvalid) {
                                        stream->HandleAsyncEvent (event);
                                    }
                                }
                            }
                        }
                    }
                }
            #endif // defined (TOOLCHAIN_OS_Windows)
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        void AsyncIoEventQueue::Break () {
        #if defined (TOOLCHAIN_OS_Windows)
            if (!PostQueuedCompletionStatus (handle, 0, 0, 0)) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE);
            }
        #else // defined (TOOLCHAIN_OS_Windows)
            THEKOGANS_UTIL_TRY {
                writePipe.Write ("\0", 1);
            }
            THEKOGANS_UTIL_CATCH (util::Exception) {
                // Prevent the case where an application calls Break
                // repeatedly without calling WaitForEvents.
                if (exception.GetErrorCode () != EAGAIN &&
                        exception.GetErrorCode () != EWOULDBLOCK) {
                    THEKOGANS_UTIL_RETHROW_EXCEPTION (exception);
                }
            }
        #endif // defined (TOOLCHAIN_OS_Windows)
        }

        void AsyncIoEventQueue::ReleaseDeletedStreams () {
            util::LockGuard<util::SpinLock> guard (spinLock);
            while (!deletedStreamsList.empty ()) {
                Stream *stream = deletedStreamsList.pop_front ();
                stream->Release ();
            }
        }

    #if defined (TOOLCHAIN_OS_Linux)
        void AsyncIoEventQueue::AddStreamForEvents (
                Stream &stream,
                util::ui32 events) {
            if (registryList.contains (&stream)) {
                util::ui32 newEvents = stream.asyncInfo->events | events;
                if (newEvents > stream.asyncInfo->events) {
                    epoll_event event = {0};
                    if (util::Flags32 (newEvents).Test (Stream::AsyncInfo::EventDisconnect)) {
                        event.events |= EPOLLRDHUP;
                    }
                    if (util::Flags32 (newEvents).TestAny (
                            Stream::AsyncInfo::EventRead |
                            Stream::AsyncInfo::EventReadFrom |
                            Stream::AsyncInfo::EventReadMsg)) {
                        event.events |= EPOLLIN;
                    }
                    if (util::Flags32 (newEvents).TestAny (
                            Stream::AsyncInfo::EventConnect |
                            Stream::AsyncInfo::EventShutdown |
                            Stream::AsyncInfo::EventWrite |
                            Stream::AsyncInfo::EventWriteTo |
                            Stream::AsyncInfo::EventWriteMsg)) {
                        event.events |= EPOLLOUT;
                    }
                    event.data.u64 = stream.asyncInfo->token;
                    if (epoll_ctl (handle,
                            stream.asyncInfo->events == 0 ? EPOLL_CTL_ADD : EPOLL_CTL_MOD,
                            stream.handle, &event) < 0) {
                        THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                            THEKOGANS_UTIL_OS_ERROR_CODE);
                    }
                    newEvents ^= stream.asyncInfo->events;
                    stream.asyncInfo->events |= newEvents;
                }
            }
        }

        void AsyncIoEventQueue::DeleteStreamForEvents (
                Stream &stream,
                util::ui32 events) {
            util::ui32 newEvents = stream.asyncInfo->events & ~events;
            if (newEvents < stream.asyncInfo->events) {
                if (newEvents != 0) {
                    epoll_event epollEvent = {0};
                    if (util::Flags32 (newEvents).Test (
                            Stream::AsyncInfo::EventDisconnect)) {
                        epollEvent.events |= EPOLLRDHUP;
                    }
                    if (util::Flags32 (newEvents).TestAny (
                            Stream::AsyncInfo::EventRead |
                            Stream::AsyncInfo::EventReadFrom |
                            Stream::AsyncInfo::EventReadMsg)) {
                        epollEvent.events |= EPOLLIN;
                    }
                    if (util::Flags32 (newEvents).TestAny (
                            Stream::AsyncInfo::EventConnect |
                            Stream::AsyncInfo::EventShutdown |
                            Stream::AsyncInfo::EventWrite |
                            Stream::AsyncInfo::EventWriteTo |
                            Stream::AsyncInfo::EventWriteMsg)) {
                        epollEvent.events |= EPOLLOUT;
                    }
                    epollEvent.data.u64 = stream.asyncInfo->token;
                    if (epoll_ctl (handle, EPOLL_CTL_MOD, stream.handle, &epollEvent) < 0) {
                        THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                            THEKOGANS_UTIL_OS_ERROR_CODE);
                    }
                }
                else if (epoll_ctl (handle, EPOLL_CTL_DEL, stream.handle, 0) < 0) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_UTIL_OS_ERROR_CODE);
                }
                stream.asyncInfo->events = newEvents;
            }
        }
    #elif defined (TOOLCHAIN_OS_OSX)
        void AsyncIoEventQueue::AddStreamForEvents (
                Stream &stream,
                util::ui32 events) {
            if (registryList.contains (&stream)) {
                util::ui32 newEvents = stream.asyncInfo->events | events;
                if (newEvents > stream.asyncInfo->events) {
                    newEvents ^= stream.asyncInfo->events;
                    if (util::Flags32 (newEvents).TestAny (
                            Stream::AsyncInfo::EventRead |
                            Stream::AsyncInfo::EventReadFrom |
                            Stream::AsyncInfo::EventReadMsg)) {
                        keventStruct kqueueEvent = {0};
                        keventSet (&kqueueEvent, stream.handle, EVFILT_READ, EV_ADD, 0, 0, stream.asyncInfo->token);
                        if (keventFunc (handle, &kqueueEvent, 1, 0, 0, 0) < 0) {
                            THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                                THEKOGANS_UTIL_OS_ERROR_CODE);
                        }
                    }
                    if (util::Flags32 (newEvents).TestAny (
                            Stream::AsyncInfo::EventConnect |
                            Stream::AsyncInfo::EventShutdown |
                            Stream::AsyncInfo::EventWrite |
                            Stream::AsyncInfo::EventWriteTo |
                            Stream::AsyncInfo::EventWriteMsg)) {
                        keventStruct kqueueEvent = {0};
                        keventSet (&kqueueEvent, stream.handle, EVFILT_WRITE, EV_ADD, 0, 0, stream.asyncInfo->token);
                        if (keventFunc (handle, &kqueueEvent, 1, 0, 0, 0) < 0) {
                            THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                                THEKOGANS_UTIL_OS_ERROR_CODE);
                        }
                    }
                    stream.asyncInfo->events |= newEvents;
                }
            }
        }

        void AsyncIoEventQueue::DeleteStreamForEvents (
                Stream &stream,
                util::ui32 events) {
            util::ui32 newEvents = stream.asyncInfo->events & ~events;
            if (newEvents < stream.asyncInfo->events) {
                newEvents = stream.asyncInfo->events & ~newEvents;
                if (util::Flags32 (newEvents).TestAny (
                        Stream::AsyncInfo::EventRead |
                        Stream::AsyncInfo::EventReadFrom |
                        Stream::AsyncInfo::EventReadMsg)) {
                    keventStruct kqueueEvent = {0};
                    keventSet (&kqueueEvent, stream.handle, EVFILT_READ, EV_DELETE, 0, 0, 0);
                    if (keventFunc (handle, &kqueueEvent, 1, 0, 0, 0) < 0) {
                        THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                            THEKOGANS_UTIL_OS_ERROR_CODE);
                    }
                }
                if (util::Flags32 (newEvents).TestAny (
                        Stream::AsyncInfo::EventConnect |
                        Stream::AsyncInfo::EventShutdown |
                        Stream::AsyncInfo::EventWrite |
                        Stream::AsyncInfo::EventWriteTo |
                        Stream::AsyncInfo::EventWriteMsg)) {
                    keventStruct kqueueEvent = {0};
                    keventSet (&kqueueEvent, stream.handle, EVFILT_WRITE, EV_DELETE, 0, 0, 0);
                    if (keventFunc (handle, &kqueueEvent, 1, 0, 0, 0) < 0) {
                        THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                            THEKOGANS_UTIL_OS_ERROR_CODE);
                    }
                }
                stream.asyncInfo->events &= ~newEvents;
            }
        }
    #endif // defined (TOOLCHAIN_OS_Linux)

    #if defined (TOOLCHAIN_OS_Windows)
        GlobalAsyncIoEventQueue::GlobalAsyncIoEventQueue (
                util::ui32 concurrentThreads,
                util::i32 priority,
                util::ui32 affinity) :
                AsyncIoEventQueue (concurrentThreads),
    #elif defined (TOOLCHAIN_OS_Linux)
        GlobalAsyncIoEventQueue::GlobalAsyncIoEventQueue (
                util::ui32 maxSize,
                util::i32 priority,
                util::ui32 affinity) :
                AsyncIoEventQueue (maxSize),
    #elif defined (TOOLCHAIN_OS_OSX)
        GlobalAsyncIoEventQueue::GlobalAsyncIoEventQueue (
                util::i32 priority,
                util::ui32 affinity) :
    #endif // defined (TOOLCHAIN_OS_Windows)
                Thread ("GlobalAsyncIoEventQueue") {
            Create (priority, affinity);
        }

        void GlobalAsyncIoEventQueue::Run () throw () {
            while (1) {
                THEKOGANS_UTIL_TRY {
                    WaitForEvents ();
                }
                THEKOGANS_UTIL_CATCH_AND_LOG_SUBSYSTEM (THEKOGANS_STREAM)
            }
        }

    } // namespace stream
} // namespace thekogans
