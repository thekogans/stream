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

    #if defined (TOOLCHAIN_OS_Linux)
        #define EPOLL_CTL(op)\
            epoll_event event = {0};\
            event.events = EPOLLRDHUP;\
            if (!in.empty ()) {\
                event.events |= EPOLLIN;\
            }\
            if (!out.empty ()) {\
                event.events |= EPOLLOUT;\
            }\
            event.data.u64 = token.GetValue ();\
            epoll_ctl (AsyncIoEventQueue::Instance ().GetHandle (), op, handle, &event);
    #endif // defined (TOOLCHAIN_OS_Linux)

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
                EPOLL_CTL (EPOLL_CTL_ADD)
            #endif // defined (TOOLCHAIN_OS_Windows)
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        Stream::~Stream () {
        #if !defined (TOOLCHAIN_OS_Windows)
            auto deleteOverlapped = [] (Overlapped *overlapped) -> bool {
                delete overlapped;
                return true;
            };
            // NOTE: No lock is taken here as by the time we enter the
            // dtor all shared references have been released. After
            // that happens the Stream::WeakPtr registered with
            // StreamRegistry will always return NULL.
            in.clear (deleteOverlapped);
            out.clear (deleteOverlapped);
        #if defined (TOOLCHAIN_OS_Linux)
            EPOLL_CTL (EPOLL_CTL_DEL);
        #endif // defined (TOOLCHAIN_OS_Linux)
        #endif // !defined (TOOLCHAIN_OS_Windows)
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

    #if defined (TOOLCHAIN_OS_Windows)
        void Stream::ExecOverlapped (Overlapped &overlapped) throw () {
            ssize_t result = overlapped.Prolog (*this);
            if (result > 0) {
                // A slight departure in logic from the ExecOverlapped below.
                // Under normal circumstances, Epilog will (should) always return
                // true on Windows as there are no second chances for overlapped.
                // But even if one decides to return false we still want to call
                // HandleOverlapped because, again, on Windows the callback is per
                // overlapped and therefore that overlapped is handled as far as
                // the os is concerned.
                overlapped.Epilog (*this);
                HandleOverlapped (overlapped);
            }
            else if (result == 0) {
                HandleDisconnect ();
            }
            else /*result < 0*/ {
                THEKOGANS_UTIL_ERROR_CODE errorCode = overlapped.GetError ();
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
                }
                else if (errorCode != STATUS_CANCELED) {
                    HandleError (THEKOGANS_UTIL_ERROR_CODE_EXCEPTION (errorCode));
                }
            }
        }
    #else // defined (TOOLCHAIN_OS_Windows)
    #if defined (TOOLCHAIN_OS_OSX)
        #define KEVENT_FUNC(op)\
            if (&queue == &in) {\
                keventStruct event = {0};\
                keventSet (&event, handle, EVFILT_READ, op, 0, 0, token.GetValue ());\
                keventFunc (AsyncIoEventQueue::Instance ().GetHandle (), &event, 1, 0, 0, 0);\
            }\
            else if (&queue == &out) {\
                keventStruct event = {0};\
                keventSet (&event, handle, EVFILT_WRITE, op, 0, 0, token.GetValue ());\
                keventFunc (AsyncIoEventQueue::Instance ().GetHandle (), &event, 1, 0, 0, 0);\
            }
    #endif // defined (TOOLCHAIN_OS_OSX)

        void Stream::EnqOverlapped (
                Overlapped::UniquePtr overlapped,
                OverlappedQueue &queue) throw () {
            util::LockGuard<util::SpinLock> guard (spinLock);
            bool first = queue.empty ();
            queue.push_back (overlapped.release ());
            if (first) {
            #if defined (TOOLCHAIN_OS_Linux)
                EPOLL_CTL (EPOLL_CTL_MOD)
            #elif defined (TOOLCHAIN_OS_OSX)
                KEVENT_FUNC (EV_ADD)
            #endif // defined (TOOLCHAIN_OS_Linux)
            }
        }

        void Stream::DeqOverlapped (OverlappedQueue &queue) throw () {
            util::LockGuard<util::SpinLock> guard (spinLock);
            if (!queue.empty ()) {
                volatile Overlapped::UniquePtr overlapped (queue.pop_front ());
                if (queue.empty ()) {
                #if defined (TOOLCHAIN_OS_Linux)
                    EPOLL_CTL (EPOLL_CTL_MOD)
                #elif defined (TOOLCHAIN_OS_OSX)
                    KEVENT_FUNC (EV_DELETE)
                #endif // defined (TOOLCHAIN_OS_Linux)
                }
            }
        }

        bool Stream::ExecOverlapped (OverlappedQueue &queue) throw () {
            while (!queue.empty ()) {
                ssize_t result = queue.front ()->Prolog (*this);
                if (result > 0) {
                    if (queue.front ()->Epilog (*this)) {
                        HandleOverlapped (*queue.front ());
                        return true;
                    }
                }
                else if (result == 0) {
                    HandleDisconnect ();
                    return true;
                }
                else /*result < 0*/ {
                    THEKOGANS_UTIL_ERROR_CODE errorCode = queue.front ()->GetError ();
                    if (errorCode == EAGAIN || errorCode == EWOULDBLOCK) {
                        return false;
                    }
                    else {
                        HandleError (THEKOGANS_UTIL_ERROR_CODE_EXCEPTION (errorCode));
                        return true;
                    }
                }
            }
            return false;
        }
    #endif // defined (TOOLCHAIN_OS_Windows)

    } // namespace stream
} // namespace thekogans
