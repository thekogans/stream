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
#include "thekogans/util/TimeSpec.h"
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

    #if defined (TOOLCHAIN_OS_Windows)
        AsyncIoEventQueue::AsyncIoEventQueue (
                util::ui32 concurrentThreads,
                util::i32 priority,
                util::ui32 affinity) :
                Thread ("AsyncIoEventQueue"),
                handle (
                    CreateIoCompletionPort (
                        THEKOGANS_UTIL_INVALID_HANDLE_VALUE,
                        0, 0, concurrentThreads)) {
    #elif defined (TOOLCHAIN_OS_Linux)
        AsyncIoEventQueue::AsyncIoEventQueue (
                util::ui32 maxSize,
                util::i32 priority,
                util::ui32 affinity) :
                Thread ("AsyncIoEventQueue"),
                handle (epoll_create (maxSize)) {
    #elif defined (TOOLCHAIN_OS_OSX)
        AsyncIoEventQueue::AsyncIoEventQueue (
                util::i32 priority,
                util::ui32 affinity) :
                Thread ("AsyncIoEventQueue"),
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

    #if defined (TOOLCHAIN_OS_Linux)
        void AsyncIoEventQueue::SetStreamEventMask (const Stream &stream) {
            epoll_event event = {0};
            event.events = EPOLLRDHUP;
            if (!stream.in.empty () != 0) {
                event.events |= EPOLLIN;
            }
            if (!stream.out.empty ()) {
                event.events |= EPOLLOUT;
            }
            event.data.u64 = stream.GetToken ();
            if (epoll_ctl (handle, EPOLL_CTL_MOD, stream.GetHandle (), &event) < 0) {
                if (THEKOGANS_UTIL_OS_ERROR_CODE != ENOENT ||
                        epoll_ctl (handle, EPOLL_CTL_ADD, stream.GetHandle (), &event) < 0) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_UTIL_OS_ERROR_CODE);
                }
            }
        }
    #elif defined (TOOLCHAIN_OS_OSX)
        void AsyncIoEventQueue::SetStreamEventMask (Stream &stream) {
            if (!stream.in.empty () != 0) {
                keventStruct kqueueEvent = {0};
                keventSet (&kqueueEvent, stream.handle, EVFILT_READ, EV_ADD, 0, 0, stream.token);
                if (keventFunc (handle, &kqueueEvent, 1, 0, 0, 0) < 0) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_UTIL_OS_ERROR_CODE);
                }
            }
            else {
                keventStruct kqueueEvent = {0};
                keventSet (&kqueueEvent, stream.handle, EVFILT_READ, EV_DELETE, 0, 0, 0);
                if (keventFunc (handle, &kqueueEvent, 1, 0, 0, 0) < 0) {
                    THEKOGANS_UTIL_ERROR_CODE errorCode = THEKOGANS_UTIL_OS_ERROR_CODE;
                    if (errorCode != ENOENT) {
                        THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (errorCode);
                    }
                }
            }
            if (!stream.out.empty ()) {
                keventStruct kqueueEvent = {0};
                keventSet (&kqueueEvent, stream.handle, EVFILT_WRITE, EV_ADD, 0, 0, stream.token);
                if (keventFunc (handle, &kqueueEvent, 1, 0, 0, 0) < 0) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_UTIL_OS_ERROR_CODE);
                }
            }
            else {
                keventStruct kqueueEvent = {0};
                keventSet (&kqueueEvent, stream.handle, EVFILT_WRITE, EV_DELETE, 0, 0, 0);
                if (keventFunc (handle, &kqueueEvent, 1, 0, 0, 0) < 0) {
                    THEKOGANS_UTIL_ERROR_CODE errorCode = THEKOGANS_UTIL_OS_ERROR_CODE;
                    if (errorCode != ENOENT) {
                        THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (errorCode);
                    }
                }
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
                    static const ULONG maxEventsBatch = 100;
                    std::vector<OVERLAPPED_ENTRY> iocpEvents (maxEventsBatch);
                    ULONG count = 0;
                    if (!GetQueuedCompletionStatusEx (handle, iocpEvents.data (),
                            maxEventsBatch, &count, INFINITE, FALSE)) {
                        THEKOGANS_UTIL_ERROR_CODE errorCode = THEKOGANS_UTIL_OS_ERROR_CODE;
                        if (errorCode != WAIT_TIMEOUT) {
                            THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (errorCode);
                        }
                    }
                    else {
                        for (ULONG i = 0; i < count; ++i) {
                            if (iocpEvents[i].lpOverlapped != 0) {
                                std::unique_ptr<Stream::Overlapped> overlapped (
                                    (Stream::Overlapped *)iocpEvents[i].lpOverlapped);
                                Stream::SharedPtr stream = StreamRegistry::Instance ().Get (
                                    (StreamRegistry::Token)iocpEvents[i].lpCompletionKey);
                                if (stream.Get () != 0) {
                                    ssize_t count = overlapped->Prolog (stream);
                                    if (count > 0) {
                                        if (overlapped->Epilog (stream)) {
                                            stream->HandleOverlapped (*overlapped);
                                        }
                                    }
                                    else if (count == 0) {
                                        stream->HandleDisconnect ();
                                    }
                                    else {
                                        THEKOGANS_UTIL_ERROR_CODE errorCode = overlapped->GetError ();
                                        // Convert known errors to disconnect events.
                                        if (errorCode == STATUS_LOCAL_DISCONNECT ||
                                                errorCode == STATUS_REMOTE_DISCONNECT ||
                                                errorCode == STATUS_PIPE_BROKEN ||
                                                errorCode == STATUS_CONNECTION_RESET) {
                                            THEKOGANS_UTIL_LOG_SUBSYSTEM_DEBUG (
                                                THEKOGANS_STREAM,
                                                "errorCode: %s.\n",
                                                ErrorCodeTostring (errorCode).c_str ());
                                            stream->HandleDisconnect ();
                                        }
                                        else if (errorCode != STATUS_CANCELED) {
                                            THEKOGANS_UTIL_ERROR_CODE_EXCEPTION exception (errorCode);
                                            THEKOGANS_UTIL_EXCEPTION_NOTE_LOCATION (exception);
                                            stream->HandleError (exception);
                                        }
                                    }
                                }
                            }
                        }
                    }
                #elif defined (TOOLCHAIN_OS_Linux)
                    std::size_t maxEventsBatch = 100;
                    std::vector<epoll_event> epollEvents (maxEventsBatch);
                    int count = epoll_wait (handle, epollEvents.data (), maxEventsBatch, -1);
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
                                    Socket::SharedPtr socket = util::dynamic_refcounted_sharedptr_cast<Socket> (stream);
                                    if (socket.Get () != 0) {
                                        THEKOGANS_UTIL_ERROR_CODE errorCode = socket->GetErrorCode ();
                                        if (errorCode == EPIPE) {
                                            socket->HandleDisconnect ();
                                        }
                                        else {
                                            socket->HandleError (
                                                THEKOGANS_UTIL_ERROR_CODE_EXCEPTION (errorCode));
                                        }
                                    }
                                    else {
                                        stream->HandleError (
                                            THEKOGANS_UTIL_STRING_EXCEPTION ("%s", "Unknown stream error."));
                                    }
                                }
                                else {
                                    if ((epollEvents[i].events & EPOLLRDHUP) || (epollEvents[i].events & EPOLLHUP)) {
                                        stream->HandleDisconnect ();
                                    }
                                    if (epollEvents[i].events & EPOLLIN) {
                                        for (std::unique_ptr<Stream::Overlapped>
                                                overlapped = stream->PumpAsyncIo (stream->in);
                                                overlapped.get () != 0;
                                                overlapped = stream->PumpAsyncIo (stream->in)) {
                                            stream->HandleOverlapped (*overlapped);
                                        }
                                    }
                                    if (epollEvents[i].events & EPOLLOUT) {
                                        for (std::unique_ptr<Stream::Overlapped>
                                                overlapped = stream->PumpAsyncIo (stream->out);
                                                overlapped.get () != 0;
                                                overlapped = stream->PumpAsyncIo (stream->out)) {
                                            stream->HandleOverlapped (*overlapped);
                                        }
                                    }
                                }
                            }
                        }
                    }
                #elif defined (TOOLCHAIN_OS_OSX)
                    static const std::size_t maxEventsBatch = 100;
                    std::vector<keventStruct> kqueueEvents (maxEventsBatch);
                    int count = keventFunc (handle, 0, 0, kqueueEvents.data (), maxEventsBatch, 0);
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
                            Stream::SharedPtr stream = StreamRegistry::Instance ().Get (kqueueEvents[i].udata);
                            if (stream.Get () != 0) {
                                if (kqueueEvents[i].flags & EV_ERROR) {
                                    stream->HandleError (
                                        THEKOGANS_UTIL_ERROR_CODE_EXCEPTION (
                                            (THEKOGANS_UTIL_ERROR_CODE)kqueueEvents[i].data));
                                }
                                else if (kqueueEvents[i].flags & EV_EOF) {
                                    // *** HACK ***
                                    // If no one is listening on the other side, kqueue returns
                                    // EV_EOF instead of ECONNREFUSED. Simulate an error that would
                                    // be returned if we did a blocking connect.
                                    if (!stream->in.empty () &&
                                            stream->in.front ()->GetName () == TCPSocket::ConnectOverlapped::NAME) {
                                        stream->HandleError (
                                            THEKOGANS_UTIL_ERROR_CODE_EXCEPTION (ECONNREFUSED));
                                    }
                                    // *** HACK ***
                                    else {
                                        stream->HandleDisconnect ();
                                    }
                                }
                                else if (kqueueEvents[i].filter == EVFILT_READ) {
                                    for (std::unique_ptr<Stream::Overlapped>
                                            overlapped = stream->PumpAsyncIo (stream->in);
                                            overlapped.get () != 0;
                                            overlapped = stream->PumpAsyncIo (stream->in)) {
                                        stream->HandleOverlapped (*overlapped);
                                    }
                                }
                                else if (kqueueEvents[i].filter == EVFILT_WRITE) {
                                    for (std::unique_ptr<Stream::Overlapped>
                                            overlapped = stream->PumpAsyncIo (stream->out);
                                            overlapped.get () != 0;
                                            overlapped = stream->PumpAsyncIo (stream->out)) {
                                        stream->HandleOverlapped (*overlapped);
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
