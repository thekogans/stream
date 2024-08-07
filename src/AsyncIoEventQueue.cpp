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
    #include "thekogans/util/os/windows/WindowsHeader.h"
#elif defined (TOOLCHAIN_OS_Linux)
    #include <sys/epoll.h>
#elif defined (TOOLCHAIN_OS_OSX)
    #include <sys/types.h>
    #include <sys/event.h>
    #include <sys/time.h>
    #include <cassert>
#endif // defined (TOOLCHAIN_OS_Windows)
#include <vector>
#include "thekogans/stream/Stream.h"
#if !defined (TOOLCHAIN_OS_Windows)
    #include "thekogans/stream/Socket.h"
#endif // !defined (TOOLCHAIN_OS_Windows)
#include "thekogans/stream/Overlapped.h"
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

        void AsyncIoEventQueue::Run () throw () {
            while (1) {
            #if defined (TOOLCHAIN_OS_Windows)
                static const ULONG maxEventsBatch = 100;
                std::vector<OVERLAPPED_ENTRY> iocpEvents (maxEventsBatch);
                ULONG count = 0;
                GetQueuedCompletionStatusEx (
                    handle,
                    iocpEvents.data (),
                    maxEventsBatch,
                    &count,
                    INFINITE,
                    FALSE);
                for (ULONG i = 0; i < count; ++i) {
                    if (iocpEvents[i].lpOverlapped != 0) {
                        Overlapped::SharedPtr overlapped (
                            (Overlapped *)iocpEvents[i].lpOverlapped, false);
                        Stream::SharedPtr stream = StreamRegistry::Instance ()->Get (
                            (StreamRegistry::Token::ValueType)iocpEvents[i].lpCompletionKey);
                        if (stream != nullptr) {
                            overlapped->Exec (stream);
                        }
                    }
                }
            #elif defined (TOOLCHAIN_OS_Linux)
                std::size_t maxEventsBatch = 100;
                std::vector<epoll_event> epollEvents (maxEventsBatch);
                for (int i = 0,
                        count = epoll_wait (handle, epollEvents.data (), maxEventsBatch, -1);
                        i < count; ++i) {
                    Stream::SharedPtr stream =
                        StreamRegistry::Instance ().Get (epollEvents[i].data.u64);
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
                                    stream->Produce (
                                        std::bind (
                                            &StreamEvents::OnStreamDisconnect,
                                            std::placeholders::_1,
                                            stream));
                                }
                                else {
                                    stream->Produce (
                                        std::bind (
                                            &StreamEvents::OnStreamError,
                                            std::placeholders::_1,
                                            stream,
                                            new THEKOGANS_UTIL_ERROR_CODE_EXCEPTION (errorCode)));
                                }
                            }
                            else {
                                stream->Produce (
                                    std::bind (
                                        &StreamEvents::OnStreamError,
                                        std::placeholders::_1,
                                        stream,
                                        new THEKOGANS_UTIL_STRING_EXCEPTION (
                                            "Unknown stream (%s) error.",
                                            stream->type ().name ())));
                            }
                        }
                        else if ((epollEvents[i].events & EPOLLRDHUP) ||
                                (epollEvents[i].events & EPOLLHUP)) {
                            stream->Produce (
                                std::bind (
                                    &StreamEvents::OnStreamDisconnect,
                                    std::placeholders::_1,
                                    stream));
                        }
                        else {
                            if (epollEvents[i].events & EPOLLIN) {
                                Overlapped::SharedPtr overlapped;
                                while ((overlapped = stream->HeadOverlapped (stream->in)) != nullptr &&
                                        overlapped->Exec (stream)) {
                                    stream->DeqOverlapped (stream->in);
                                }
                            }
                            if (epollEvents[i].events & EPOLLOUT) {
                                Overlapped::SharedPtr overlapped;
                                while ((overlapped = stream->HeadOverlapped (stream->out)) != nullptr &&
                                        overlapped->Exec (stream)) {
                                    stream->DeqOverlapped (stream->out);
                                }
                            }
                        }
                    }
                }
            #elif defined (TOOLCHAIN_OS_OSX)
                static const std::size_t maxEventsBatch = 100;
                std::vector<keventStruct> kqueueEvents (maxEventsBatch);
                for (int i = 0,
                        count = keventFunc (handle, 0, 0, kqueueEvents.data (), maxEventsBatch, 0);
                        i < count; ++i) {
                    Stream::SharedPtr stream =
                        StreamRegistry::Instance ().Get (kqueueEvents[i].udata);
                    if (stream.Get () != 0) {
                        if (kqueueEvents[i].flags & EV_ERROR) {
                            stream->Produce (
                                std::bind (
                                    &StreamEvents::OnStreamError,
                                    std::placeholders::_1,
                                    stream,
                                    new THEKOGANS_UTIL_ERROR_CODE_EXCEPTION (
                                        (THEKOGANS_UTIL_ERROR_CODE)kqueueEvents[i].data)));
                        }
                        else if (kqueueEvents[i].flags & EV_EOF) {
                            // If no one is listening on the other side, kqueue returns
                            // EV_EOF instead of an appropriate error code. Simulate an
                            // error that would be returned if we did a blocking connect.
                            Socket::SharedPtr socket =
                                util::dynamic_refcounted_sharedptr_cast<Socket> (stream);
                            if (socket.Get () != 0) {
                                THEKOGANS_UTIL_ERROR_CODE errorCode = socket->GetErrorCode ();
                                if (errorCode == ETIMEDOUT ||
                                        errorCode == ECONNREFUSED ||
                                        errorCode == EHOSTUNREACH) {
                                    stream->Produce (
                                        std::bind (
                                            &StreamEvents::OnStreamError,
                                            std::placeholders::_1,
                                            stream,
                                            new THEKOGANS_UTIL_ERROR_CODE_EXCEPTION (errorCode)));
                                    continue;
                                }
                            }
                            stream->Produce (
                                std::bind (
                                    &StreamEvents::OnStreamDisconnect,
                                    std::placeholders::_1,
                                    stream));
                        }
                        else if (kqueueEvents[i].filter == EVFILT_READ) {
                            Overlapped::SharedPtr overlapped;
                            while ((overlapped = stream->HeadOverlapped (stream->in)) != nullptr &&
                                    overlapped->Exec (stream)) {
                                stream->DeqOverlapped (stream->in);
                            }
                        }
                        else if (kqueueEvents[i].filter == EVFILT_WRITE) {
                            Overlapped::SharedPtr overlapped;
                            while ((overlapped = stream->HeadOverlapped (stream->out)) != nullptr &&
                                    overlapped->Exec (stream)) {
                                stream->DeqOverlapped (stream->out);
                            }
                        }
                    }
                }
            #endif // defined (TOOLCHAIN_OS_Windows)
            }
        }

    } // namespace stream
} // namespace thekogans
