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
#include "thekogans/util/TimeSpec.h"
#include "thekogans/util/SpinLock.h"
#include "thekogans/stream/Config.h"
#include "thekogans/stream/Stream.h"
#if !defined (TOOLCHAIN_OS_Windows)
    #include "thekogans/stream/Pipe.h"
#endif // !defined (TOOLCHAIN_OS_Windows)

namespace thekogans {
    namespace stream {

        /// \struct AsyncIoEventQueue AsyncIoEventQueue.h thekogans/stream/AsyncIoEventQueue.h
        ///
        /// \brief
        /// An AsyncIoEventQueue is an event queue for monitoring
        /// asynchronous streams. It provides a simple, and
        /// (mostly) uniform api around platform specific interfaces
        /// (Windows - iocp, Linux - epoll, and OS X - kqueue).
        ///
        /// The unfortunate part is that while all three platforms
        /// provide native apis for such things, their semantics are
        /// quite different. Windows uses a pro-active approach (start
        /// an overlapped operation, and monitor it's completion
        /// status), while Linux and OS X use a reactive approach
        /// (monitor these handles, and let me know when an event I am
        /// interested in occurs). These two different philosophies
        /// mean that, while the AsyncIoEventQueue interface to the
        /// platform specific event queues is the same on all
        /// platforms, it's semantics are not. The stream library
        /// paves over this inconsistency by providing a single
        /// hybrid model that is maintained by all other classes.
        /// The model uses the best features from both approaches
        /// to provide a simple and elegant solution to async io.
        /// It's hybrid because on the read side it uses a POSIX
        /// reactive approach (let me know when a buffer arrived),
        /// and on the write side it uses a Windows pro-active
        /// approach (write this buffer, and let me know when done).
        /// Again, unfortunately, due to the semantic differences
        /// between the two approaches, I can't sweep all the
        /// details under a rug. This is why there are multiple
        /// versions of the ctor. One for Windows, one for Linux
        /// and one for OS X. I provided what I would consider
        /// sensible defaults, and if they work for you, great!
        /// Your code will truly be platform independent. If
        /// not, you will need to provide your own values using
        /// a #if defined (TOOLCHAIN_OS_[Windows | Linux | OSX]).

        struct _LIB_THEKOGANS_STREAM_DECL AsyncIoEventQueue :
                public util::Singleton<AsyncIoEventQueue, util::SpinLock>,
                public util::Thread {
            /// \brief
            /// Declare \see{RefCounted} pointers.
            THEKOGANS_UTIL_DECLARE_REF_COUNTED_POINTERS (AsyncIoEventQueue)

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
            ~AsyncIoEventQueue ();

            /// \brief
            /// Return the queue handle.
            /// \return Queue handle.
            inline THEKOGANS_UTIL_HANDLE GetHandle () const {
                return handle;
            }

        #if !defined (TOOLCHAIN_OS_Windows)
            /// \brief
            /// Used internally by epoll and kqueue variants to
            /// add a 'stream is ready for events' notification.
            /// \param[in] stream \see{Stream} that wants to be notified
            /// when an event(s) it's interested in has occurred.
            void SetStreamEventMask (const Stream &stream);
        #endif // !defined (TOOLCHAIN_OS_Windows)

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
