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
#if defined (TOOLCHAIN_OS_Linux)
    #include <sys/epoll.h>
#elif defined (TOOLCHAIN_OS_OSX)
    #include <sys/types.h>
    #include <sys/event.h>
    #include <sys/time.h>
#endif // defined (TOOLCHAIN_OS_Linux)
#include <cstdio>
#include <cstdarg>
#include <cassert>
#include "thekogans/util/LockGuard.h"
#include "thekogans/util/Exception.h"
#include "thekogans/util/LoggerMgr.h"
#include "thekogans/stream/AsyncIoEventQueue.h"
#include "thekogans/stream/Stream.h"

namespace thekogans {
    namespace stream {

        Stream::Stream (THEKOGANS_UTIL_HANDLE handle_) :
                handle (handle_),
                token (this) {
            if (handle != THEKOGANS_UTIL_INVALID_HANDLE_VALUE) {
            #if defined (TOOLCHAIN_OS_Windows)
                if (CreateIoCompletionPort (
                        handle, AsyncIoEventQueue::Instance ().GetHandle (), (ULONG_PTR)token.GetValue (), 0) == 0) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_UTIL_OS_ERROR_CODE);
                }
            #elif defined (TOOLCHAIN_OS_Linux)
                epoll_event event = {0};
                event.events = EPOLLRDHUP;
                event.data.u64 = token.GetValue ();
                if (epoll_ctl (AsyncIoEventQueue::Instance ().GetHandle (), EPOLL_CTL_ADD, handle, &event) < 0) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_UTIL_OS_ERROR_CODE);
                }
            #endif // defined (TOOLCHAIN_OS_Windows)
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        Stream::~Stream () {
            Close ();
        }

        void Stream::Close () throw () {
            if (handle != THEKOGANS_UTIL_INVALID_HANDLE_VALUE) {
            #if defined (TOOLCHAIN_OS_Windows)
                ::CloseHandle (handle);
            #else // defined (TOOLCHAIN_OS_Windows)
                close (handle);
            #endif // defined (TOOLCHAIN_OS_Windows)
                handle = THEKOGANS_UTIL_INVALID_HANDLE_VALUE;
            }
        }

        void Stream::Write (
                const void *buffer,
                std::size_t bufferLength) {
            if (buffer != 0 && bufferLength > 0) {
                util::Buffer buffer_ (
                    util::NetworkEndian,
                    (const util::ui8 *)buffer,
                    (const util::ui8 *)buffer + bufferLength);
                Write (std::move (buffer_));
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        void Stream::HandleError (const util::Exception &exception) throw () {
            Produce (
                std::bind (
                    &StreamEvents::OnStreamError,
                    std::placeholders::_1,
                    SharedPtr (this),
                    exception));
        }

        void Stream::HandleDisconnect () throw () {
            Produce (
                std::bind (
                    &StreamEvents::OnStreamDisconnect,
                    std::placeholders::_1,
                    SharedPtr (this)));
        }

    #if !defined (TOOLCHAIN_OS_Windows)
        void Stream::EnqOverlapped (
                Overlapped::UniquePtr overlapped,
                Overlapped::Queue &queue,
                bool front) throw () {
            util::LockGuard<util::SpinLock> guard (spinLock);
            bool setMask = queue.empty ();
            if (front) {
                queue.push_front (std::move (overlapped));
            }
            else {
                queue.push_back (std::move (overlapped));
            }
            if (setMask) {
            #if defined (TOOLCHAIN_OS_Linux)
                epoll_event event = {0};
                event.events = EPOLLRDHUP;
                if (!in.empty ()) {
                    event.events |= EPOLLIN;
                }
                if (!out.empty ()) {
                    event.events |= EPOLLOUT;
                }
                event.data.u64 = token.GetValue ();
                epoll_ctl (AsyncIoEventQueue::Instance ().GetHandle (), EPOLL_CTL_MOD, handle, &event);
            #elif defined (TOOLCHAIN_OS_OSX)
                if (!in.empty ()) {
                    keventStruct event = {0};
                    keventSet (&event, handle, EVFILT_READ, EV_ADD, 0, 0, token.GetValue ());
                    keventFunc (AsyncIoEventQueue::Instance ().GetHandle (), &event, 1, 0, 0, 0);
                }
                if (!out.empty ()) {
                    keventStruct event = {0};
                    keventSet (&event, handle, EVFILT_WRITE, EV_ADD, 0, 0, token.GetValue ());
                    keventFunc (AsyncIoEventQueue::Instance ().GetHandle (), &event, 1, 0, 0, 0);
                }
            #endif // defined (TOOLCHAIN_OS_Linux)
            }
        }

        Overlapped::UniquePtr Stream::DeqOverlapped (Overlapped::Queue &queue) throw () {
            Overlapped::UniquePtr overlapped;
            util::LockGuard<util::SpinLock> guard (spinLock);
            if (!queue.empty ()) {
                overlapped = std::move (queue.front ());
                queue.pop_front ();
                if (queue.empty ()) {
                #if defined (TOOLCHAIN_OS_Linux)
                    epoll_event event = {0};
                    event.events = EPOLLRDHUP;
                    if (!in.empty ()) {
                        event.events |= EPOLLIN;
                    }
                    if (!out.empty ()) {
                        event.events |= EPOLLOUT;
                    }
                    event.data.u64 = token.GetValue ();
                    epoll_ctl (AsyncIoEventQueue::Instance ().GetHandle (), EPOLL_CTL_MOD, handle, &event);
                #elif defined (TOOLCHAIN_OS_OSX)
                    if (in.empty ()) {
                        keventStruct event = {0};
                        keventSet (&event, handle, EVFILT_READ, EV_DELETE, 0, 0, 0);
                        keventFunc (AsyncIoEventQueue::Instance ().GetHandle (), &event, 1, 0, 0, 0);
                    }
                    if (out.empty ()) {
                        keventStruct event = {0};
                        keventSet (&event, handle, EVFILT_WRITE, EV_DELETE, 0, 0, 0);
                        keventFunc (AsyncIoEventQueue::Instance ().GetHandle (), &event, 1, 0, 0, 0);
                    }
                #endif // defined (TOOLCHAIN_OS_Linux)
                }
            }
            return overlapped;
        }
    #endif // !defined (TOOLCHAIN_OS_Windows)

        bool Stream::ExecOverlapped (Overlapped &overlapped) throw () {
            while (1) {
                ssize_t result = overlapped.Prolog (*this);
                if (result > 0) {
                    if (overlapped.Epilog (*this)) {
                        HandleOverlapped (overlapped);
                        return true;
                    }
                }
                else if (result == 0) {
                    HandleDisconnect ();
                    return true;
                }
                else /*result < 0*/ {
                    THEKOGANS_UTIL_ERROR_CODE errorCode = overlapped.GetError ();
                #if defined (TOOLCHAIN_OS_Windows)
                    // Convert known errors to disconnect events.
                    #define STATUS_CANCELED 0xC0000120
                    #define STATUS_LOCAL_DISCONNECT 0xC000013B
                    #define STATUS_REMOTE_DISCONNECT 0xC000013C
                    #define STATUS_PIPE_BROKEN 0xC000014b
                    #define STATUS_CONNECTION_RESET 0xC000020D
                    if (errorCode == STATUS_LOCAL_DISCONNECT ||
                            errorCode == STATUS_REMOTE_DISCONNECT ||
                            errorCode == STATUS_PIPE_BROKEN ||
                            errorCode == STATUS_CONNECTION_RESET) {
                        HandleDisconnect ();
                        return true;
                    }
                    else if (errorCode == STATUS_CANCELED) {
                        return true;
                    }
                #else // defined (TOOLCHAIN_OS_Windows)
                    if (errorCode == EAGAIN || errorCode == EWOULDBLOCK) {
                        return false;
                    }
                #endif // defined (TOOLCHAIN_OS_Windows)
                    else {
                        HandleError (THEKOGANS_UTIL_ERROR_CODE_EXCEPTION (errorCode));
                        return true;
                    }
                }
            }
        }

    } // namespace stream
} // namespace thekogans
