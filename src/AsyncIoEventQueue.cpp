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
#if defined (TOOLCHAIN_OS_Linux)
    #include "thekogans/stream/Socket.h"
#endif // defined (TOOLCHAIN_OS_Linux)
#include "thekogans/stream/AsyncIoEventQueue.h"

namespace thekogans {
    namespace stream {

        AsyncIoEventQueue::AsyncIoEventQueue (
        #if defined (TOOLCHAIN_OS_Windows)
                util::ui32 concurrentThreads,
        #elif defined (TOOLCHAIN_OS_Linux)
                util::ui32 maxSize,
        #endif // defined (TOOLCHAIN_OS_Windows)
                util::i32 priority,
                util::ui32 affinity) :
                Thread ("AsyncIoEventQueue"),
            #if defined (TOOLCHAIN_OS_Windows)
                handle (
                    CreateIoCompletionPort (
                        THEKOGANS_UTIL_INVALID_HANDLE_VALUE,
                        0, 0, concurrentThreads)) {
            #elif defined (TOOLCHAIN_OS_Linux)
                handle (epoll_create (maxSize)) {
            #elif defined (TOOLCHAIN_OS_OSX)
                handle (kqueue ()) {
            #endif // defined (TOOLCHAIN_OS_Windows)
            if (handle == THEKOGANS_UTIL_INVALID_HANDLE_VALUE) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE);
            }
            Create (priority, affinity);
        }

        AsyncIoEventQueue::~AsyncIoEventQueue () {
        #if defined (TOOLCHAIN_OS_Windows)
            CloseHandle (handle);
        #elif defined (TOOLCHAIN_OS_Linux)
            close (handle);
        #elif defined (TOOLCHAIN_OS_OSX)
            close (handle);
        #endif // defined (TOOLCHAIN_OS_Windows)
        }

        void AsyncIoEventQueue::AddStream (Stream &stream) {
            if (stream.IsOpen ()) {
            #if defined (TOOLCHAIN_OS_Windows)
                if (CreateIoCompletionPort (
                        stream.handle, handle, (ULONG_PTR)&stream, 0) == 0) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_UTIL_OS_ERROR_CODE);
                }
            #endif // defined (TOOLCHAIN_OS_Windows)
                stream.InitAsyncIo ();
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        void AsyncIoEventQueue::DeleteStream (Stream &stream) {
            if (stream.IsOpen ()) {
            #if defined (TOOLCHAIN_OS_Windows)
                CancelIoEx (stream.handle, 0);
            #else // defined (TOOLCHAIN_OS_Windows)
                DeleteStreamForEvents (stream, stream.events);
            #endif // defined (TOOLCHAIN_OS_Windows)
                stream.TerminateAsyncIo ();
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

    #if defined (TOOLCHAIN_OS_Linux)
        void AsyncIoEventQueue::AddStreamForEvents (
                Stream &stream,
                util::ui32 events) {
            util::ui32 newEvents = stream.events | events;
            if (newEvents > stream.events) {
                epoll_event event = {0};
                if (util::Flags32 (newEvents).Test (Stream::EventDisconnect)) {
                    event.events |= EPOLLRDHUP;
                }
                if (util::Flags32 (newEvents).TestAny (
                        Stream::EventRead |
                        Stream::EventReadFrom |
                        Stream::EventReadMsg)) {
                    event.events |= EPOLLIN;
                }
                if (util::Flags32 (newEvents).TestAny (
                        Stream::EventConnect |
                        Stream::EventShutdown |
                        Stream::EventWrite |
                        Stream::EventWriteTo |
                        Stream::EventWriteMsg)) {
                    event.events |= EPOLLOUT;
                }
                event.data.u64 = stream.token;
                if (epoll_ctl (handle,
                        stream.events == 0 ? EPOLL_CTL_ADD : EPOLL_CTL_MOD,
                        stream.handle, &event) < 0) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_UTIL_OS_ERROR_CODE);
                }
                newEvents ^= stream.events;
                stream.events |= newEvents;
            }
        }

        void AsyncIoEventQueue::DeleteStreamForEvents (
                Stream &stream,
                util::ui32 events) {
            util::ui32 newEvents = stream.events & ~events;
            if (newEvents < stream.events) {
                if (newEvents != 0) {
                    epoll_event epollEvent = {0};
                    if (util::Flags32 (newEvents).Test (
                            Stream::EventDisconnect)) {
                        epollEvent.events |= EPOLLRDHUP;
                    }
                    if (util::Flags32 (newEvents).TestAny (
                            Stream::EventRead |
                            Stream::EventReadFrom |
                            Stream::EventReadMsg)) {
                        epollEvent.events |= EPOLLIN;
                    }
                    if (util::Flags32 (newEvents).TestAny (
                            Stream::EventConnect |
                            Stream::EventShutdown |
                            Stream::EventWrite |
                            Stream::EventWriteTo |
                            Stream::EventWriteMsg)) {
                        epollEvent.events |= EPOLLOUT;
                    }
                    epollEvent.data.u64 = stream.token;
                    if (epoll_ctl (handle, EPOLL_CTL_MOD, stream.handle, &epollEvent) < 0) {
                        THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                            THEKOGANS_UTIL_OS_ERROR_CODE);
                    }
                }
                else if (epoll_ctl (handle, EPOLL_CTL_DEL, stream.handle, 0) < 0) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_UTIL_OS_ERROR_CODE);
                }
                stream.events = newEvents;
            }
        }
    #elif defined (TOOLCHAIN_OS_OSX)
        void AsyncIoEventQueue::AddStreamForEvents (
                Stream &stream,
                util::ui32 events) {
            util::ui32 newEvents = stream.events | events;
            if (newEvents > stream.events) {
                newEvents ^= stream.events;
                if (util::Flags32 (newEvents).TestAny (
                        Stream::EventRead |
                        Stream::EventReadFrom |
                        Stream::EventReadMsg)) {
                    keventStruct kqueueEvent = {0};
                    keventSet (&kqueueEvent, stream.handle, EVFILT_READ, EV_ADD, 0, 0, stream.token);
                    if (keventFunc (handle, &kqueueEvent, 1, 0, 0, 0) < 0) {
                        THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                            THEKOGANS_UTIL_OS_ERROR_CODE);
                    }
                }
                if (util::Flags32 (newEvents).TestAny (
                        Stream::EventConnect |
                        Stream::EventShutdown |
                        Stream::EventWrite |
                        Stream::EventWriteTo |
                        Stream::EventWriteMsg)) {
                    keventStruct kqueueEvent = {0};
                    keventSet (&kqueueEvent, stream.handle, EVFILT_WRITE, EV_ADD, 0, 0, stream.token);
                    if (keventFunc (handle, &kqueueEvent, 1, 0, 0, 0) < 0) {
                        THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                            THEKOGANS_UTIL_OS_ERROR_CODE);
                    }
                }
                stream.events |= newEvents;
            }
        }

        void AsyncIoEventQueue::DeleteStreamForEvents (
                Stream &stream,
                util::ui32 events) {
            util::ui32 newEvents = stream.events & ~events;
            if (newEvents < stream.events) {
                newEvents = stream.events & ~newEvents;
                if (util::Flags32 (newEvents).TestAny (
                        Stream::EventRead |
                        Stream::EventReadFrom |
                        Stream::EventReadMsg)) {
                    keventStruct kqueueEvent = {0};
                    keventSet (&kqueueEvent, stream.handle, EVFILT_READ, EV_DELETE, 0, 0, 0);
                    if (keventFunc (handle, &kqueueEvent, 1, 0, 0, 0) < 0) {
                        THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                            THEKOGANS_UTIL_OS_ERROR_CODE);
                    }
                }
                if (util::Flags32 (newEvents).TestAny (
                        Stream::EventConnect |
                        Stream::EventShutdown |
                        Stream::EventWrite |
                        Stream::EventWriteTo |
                        Stream::EventWriteMsg)) {
                    keventStruct kqueueEvent = {0};
                    keventSet (&kqueueEvent, stream.handle, EVFILT_WRITE, EV_DELETE, 0, 0, 0);
                    if (keventFunc (handle, &kqueueEvent, 1, 0, 0, 0) < 0) {
                        THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                            THEKOGANS_UTIL_OS_ERROR_CODE);
                    }
                }
                stream.events &= ~newEvents;
            }
        }
    #endif // defined (TOOLCHAIN_OS_Linux)

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

        void AsyncIoEventQueue::Run () throw () {
            while (1) {
                THEKOGANS_UTIL_TRY {
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
                                Stream::Overlapped::SharedPtr overlapped (
                                    (Stream::Overlapped *)iocpEvents[i].lpOverlapped, false);
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
                                            overlapped->event = Stream::EventDisconnect;
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
                                if (stream.Get () != 0) {
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
                                        Socket::SharedPtr socket =
                                            util::dynamic_refcounted_sharedptr_cast<Socket> (stream);
                                        if (socket.Get () != 0) {
                                            THEKOGANS_UTIL_ERROR_CODE errorCode = socket->GetErrorCode ();
                                            if (errorCode == EPIPE) {
                                                socket->HandleAsyncEvent (Stream::EventDisconnect);
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
                                                util::Flags32 (stream->events).Test (
                                                    Stream::EventRead) ? Stream::EventRead :
                                                util::Flags32 (stream->events).Test (
                                                    Stream::EventReadFrom) ? Stream::EventReadFrom :
                                                util::Flags32 (stream->events).Test (
                                                    Stream::EventReadMsg) ? Stream::EventReadMsg :
                                                Stream::EventInvalid;
                                            if (event != Stream::EventInvalid) {
                                                stream->HandleAsyncEvent (event);
                                            }
                                        }
                                        if (epollEvents[i].events & EPOLLOUT) {
                                            util::ui32 event =
                                                util::Flags32 (stream->events).Test (
                                                    Stream::EventConnect) ? Stream::EventConnect :
                                                util::Flags32 (stream->events).Test (
                                                    Stream::EventShutdown) ? Stream::EventShutdown :
                                                util::Flags32 (stream->events).Test (
                                                    Stream::EventWrite) ? Stream::EventWrite :
                                                util::Flags32 (stream->events).Test (
                                                    Stream::EventWriteTo) ? Stream::EventWriteTo :
                                                util::Flags32 (stream->events).Test (
                                                    Stream::EventWriteMsg) ? Stream::EventWriteMsg :
                                                Stream::EventInvalid;
                                            if (event != Stream::EventInvalid) {
                                                stream->HandleAsyncEvent (event);
                                            }
                                        }
                                        if ((epollEvents[i].events & EPOLLRDHUP) || (epollEvents[i].events & EPOLLHUP)) {
                                            stream->HandleAsyncEvent (Stream::EventDisconnect);
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
                                if (stream.Get () != 0) {
                                    if (kqueueEvents[i].flags & EV_ERROR) {
                                        stream->HandleError (
                                            THEKOGANS_UTIL_ERROR_CODE_EXCEPTION (
                                                (THEKOGANS_UTIL_ERROR_CODE)kqueueEvents[i].data));
                                    }
                                    else if (kqueueEvents[i].flags & EV_EOF) {
                                        // If no one is listening on the other side, kqueue returns
                                        // EV_EOF instead of ECONNREFUSED. Simulate an error that would
                                        // be returned if we did a blocking connect.
                                        if (util::Flags32 (stream->events).Test (
                                                Stream::EventConnect)) {
                                            stream->HandleError (
                                                THEKOGANS_UTIL_ERROR_CODE_EXCEPTION (ECONNREFUSED));
                                        }
                                        else {
                                            stream->HandleAsyncEvent (Stream::EventDisconnect);
                                        }
                                    }
                                    else if (kqueueEvents[i].filter == EVFILT_READ) {
                                        util::ui32 event =
                                            util::Flags32 (stream->events).Test (
                                                Stream::EventRead) ? Stream::EventRead :
                                            util::Flags32 (stream->events).Test (
                                                Stream::EventReadFrom) ? Stream::EventReadFrom :
                                            util::Flags32 (stream->events).Test (
                                                Stream::EventReadMsg) ? Stream::EventReadMsg :
                                            Stream::EventInvalid;
                                        if (event != Stream::EventInvalid) {
                                            stream->HandleAsyncEvent (event);
                                        }
                                    }
                                    else if (kqueueEvents[i].filter == EVFILT_WRITE) {
                                        util::ui32 event =
                                            util::Flags32 (stream->events).Test (
                                                Stream::EventConnect) ? Stream::EventConnect :
                                            util::Flags32 (stream->events).Test (
                                                Stream::EventShutdown) ? Stream::EventShutdown :
                                            util::Flags32 (stream->events).Test (
                                                Stream::EventWrite) ? Stream::EventWrite :
                                            util::Flags32 (stream->events).Test (
                                                Stream::EventWriteTo) ? Stream::EventWriteTo :
                                            util::Flags32 (stream->events).Test (
                                                Stream::EventWriteMsg) ? Stream::EventWriteMsg :
                                            Stream::EventInvalid;
                                        if (event != Stream::EventInvalid) {
                                            stream->HandleAsyncEvent (event);
                                        }
                                    }
                                }
                            }
                        }
                    }
                #endif // defined (TOOLCHAIN_OS_Windows)
                }
                THEKOGANS_UTIL_CATCH_AND_LOG_SUBSYSTEM (THEKOGANS_STREAM)
            }
        }

    } // namespace stream
} // namespace thekogans
