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
            epoll_ctl (AsyncIoEventQueue::Instance ()->GetHandle (), op, handle, &event);
    #endif // defined (TOOLCHAIN_OS_Linux)

        Stream::Stream (THEKOGANS_UTIL_HANDLE handle_) :
                handle (handle_),
                token (this),
                chainRead (true) {
            if (handle != THEKOGANS_UTIL_INVALID_HANDLE_VALUE) {
            #if defined (TOOLCHAIN_OS_Windows)
                if (CreateIoCompletionPort (
                        handle,
                        AsyncIoEventQueue::Instance ()->GetHandle (),
                        (ULONG_PTR)token.GetValue (),
                        0) == 0) {
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
        #if defined (TOOLCHAIN_OS_Linux)
            EPOLL_CTL (EPOLL_CTL_DEL);
        #endif // defined (TOOLCHAIN_OS_Linux)
            Close ();
        }

        void Stream::Close () noexcept {
            if (handle != THEKOGANS_UTIL_INVALID_HANDLE_VALUE) {
            #if defined (TOOLCHAIN_OS_Windows)
                ::CloseHandle (handle);
            #else // defined (TOOLCHAIN_OS_Windows)
                close (handle);
            #endif // defined (TOOLCHAIN_OS_Windows)
                handle = THEKOGANS_UTIL_INVALID_HANDLE_VALUE;
            #if !defined (TOOLCHAIN_OS_Windows)
                util::LockGuard<util::SpinLock> guard (spinLock);
                in.clear ();
                out.clear ();
            #endif // !defined (TOOLCHAIN_OS_Windows)
            }
        }

        void Stream::Write (
                const void *buffer,
                std::size_t bufferLength) {
            if (buffer != nullptr && bufferLength > 0) {
                Write (
                    new util::NetworkBuffer (
                        (const util::ui8 *)buffer,
                        (const util::ui8 *)buffer + bufferLength));
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

    #if !defined (TOOLCHAIN_OS_Windows)
    #if defined (TOOLCHAIN_OS_OSX)
        #define KEVENT_FUNC(op)\
            if (&queue == &in) {\
                keventStruct event = {0};\
                keventSet (&event, handle, EVFILT_READ, op, 0, 0, token.GetValue ());\
                keventFunc (AsyncIoEventQueue::Instance ()->GetHandle (), &event, 1, 0, 0, 0);\
            }\
            else if (&queue == &out) {\
                keventStruct event = {0};\
                keventSet (&event, handle, EVFILT_WRITE, op, 0, 0, token.GetValue ());\
                keventFunc (AsyncIoEventQueue::Instance ()->GetHandle (), &event, 1, 0, 0, 0);\
            }
    #endif // defined (TOOLCHAIN_OS_OSX)

        void Stream::EnqOverlapped (
                Overlapped::SharedPtr overlapped,
                Overlapped::Queue &queue) noexcept {
            util::LockGuard<util::SpinLock> guard (spinLock);
            bool first = queue.empty ();
            queue.push_back (overlapped);
            if (first) {
            #if defined (TOOLCHAIN_OS_Linux)
                EPOLL_CTL (EPOLL_CTL_MOD)
            #elif defined (TOOLCHAIN_OS_OSX)
                KEVENT_FUNC (EV_ADD)
            #endif // defined (TOOLCHAIN_OS_Linux)
            }
        }

        void Stream::DeqOverlapped (Overlapped::Queue &queue) noexcept {
            util::LockGuard<util::SpinLock> guard (spinLock);
            if (!queue.empty ()) {
                queue.pop_front ();
                if (queue.empty ()) {
                #if defined (TOOLCHAIN_OS_Linux)
                    EPOLL_CTL (EPOLL_CTL_MOD)
                #elif defined (TOOLCHAIN_OS_OSX)
                    KEVENT_FUNC (EV_DELETE)
                #endif // defined (TOOLCHAIN_OS_Linux)
                }
            }
        }

        Overlapped::SharedPtr Stream::HeadOverlapped (Overlapped::Queue &queue) noexcept {
            util::LockGuard<util::SpinLock> guard (spinLock);
            return !queue.empty () ? queue.front () : Overlapped::SharedPtr ();
        }
    #endif // !defined (TOOLCHAIN_OS_Windows)

    } // namespace stream
} // namespace thekogans
