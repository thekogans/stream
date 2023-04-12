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

#if !defined (__thekogans_stream_AsyncIoEventQueue_h)
#define __thekogans_stream_AsyncIoEventQueue_h

#include <functional>
#include "thekogans/util/Environment.h"
#include "thekogans/util/Types.h"
#include "thekogans/util/Singleton.h"
#include "thekogans/util/Thread.h"
#include "thekogans/util/SpinLock.h"
#include "thekogans/stream/Config.h"

namespace thekogans {
    namespace stream {

        /// \struct AsyncIoEventQueue AsyncIoEventQueue.h thekogans/stream/AsyncIoEventQueue.h
        ///
        /// \brief
        /// An AsyncIoEventQueue \see{util::Singleton} is a background \see{util::Thread} for
        /// monitoring asynchronous streams. On Windows it's implemented using IO completion
        /// ports. On Linux it's implemented using epoll and on OS X using a kqueue.

        struct _LIB_THEKOGANS_STREAM_DECL AsyncIoEventQueue :
                public util::Singleton<AsyncIoEventQueue, util::SpinLock>,
                public util::Thread {
        private:
            /// \brief
            /// Handle to an OS specific async io event queue.
            THEKOGANS_UTIL_HANDLE handle;

        public:
            /// \brief
            /// ctor.
        #if defined (TOOLCHAIN_OS_Windows)
            enum {
                /// \brief
                /// Number of concurrent threads servicing
                /// the queue. Since AsyncIoEventQueue is
                /// the one and only, there should be very
                /// little reason to chenge this parameter.
                /// It's here for completeness, and for the
                /// one in ? times when you actually need to
                /// do something different.
                DEFAULT_CONCURRENT_THREADS = 1
            };
            /// \param[in] concurrentThreads The maximum number
            /// of threads that the operating system can allow
            /// to concurrently process I/O completion packets
            /// for the I/O completion port.
        #elif defined (TOOLCHAIN_OS_Linux)
            enum {
                /// \brief
                /// Default max queue size.
                DEFAULT_MAX_SIZE = 256
            };
            /// \param[in] maxSize Provided for completeness only.
            /// This parameter is ignored by epoll_create.
        #endif // defined (TOOLCHAIN_OS_Windows)
            /// \param[in] priority Thread priority.
            /// \param[in] affinity Thread affinity.
            AsyncIoEventQueue (
            #if defined (TOOLCHAIN_OS_Windows)
                util::ui32 concurrentThreads = DEFAULT_CONCURRENT_THREADS,
            #elif defined (TOOLCHAIN_OS_Linux)
                util::ui32 maxSize = DEFAULT_MAX_SIZE,
            #endif // defined (TOOLCHAIN_OS_Windows)
                util::i32 priority = THEKOGANS_UTIL_NORMAL_THREAD_PRIORITY,
                util::ui32 affinity = THEKOGANS_UTIL_MAX_THREAD_AFFINITY);
            /// \brief
            /// dtor.
            ~AsyncIoEventQueue ();

            /// \brief
            /// Return the queue handle.
            /// \return Queue handle.
            inline THEKOGANS_UTIL_HANDLE GetHandle () const {
                return handle;
            }

        private:
            // util::Thread
            /// \brief
            /// AsyncIoEventQueue thread.
            virtual void Run () throw () override;

            /// \brief
            /// AsyncIoEventQueue is neither copy constructable, nor assignable.
            THEKOGANS_STREAM_DISALLOW_COPY_AND_ASSIGN (AsyncIoEventQueue)
        };

    } // namespace stream
} // namespace thekogans

#endif // !defined (__thekogans_stream_AsyncIoEventQueue_h)
