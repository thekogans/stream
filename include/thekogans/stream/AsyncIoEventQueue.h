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
#include "thekogans/util/Types.h"
#include "thekogans/util/TimeSpec.h"
#include "thekogans/util/SpinLock.h"
#include "thekogans/stream/Config.h"
#include "thekogans/stream/Stream.h"
#if !defined (TOOLCHAIN_OS_Windows)
    #include "thekogans/stream/Pipe.h"
#endif // !defined (TOOLCHAIN_OS_Windows)
#include "thekogans/stream/AsyncIoEventSink.h"

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

        struct _LIB_THEKOGANS_STREAM_DECL AsyncIoEventQueue : public util::RefCounted {
            /// \brief
            /// Declare \see{RefCounted} pointers.
            THEKOGANS_UTIL_DECLARE_REF_COUNTED_POINTERS (AsyncIoEventQueue)

        private:
            /// \brief
            /// Handle to an OS specific async io event queue.
            THEKOGANS_UTIL_HANDLE handle;
        #if !defined (TOOLCHAIN_OS_Windows)
            /// \brief
            /// Implements the read end of a self-pipe.
            /// Used to break out of the WaitForEvents.
            Pipe readPipe;
            /// \brief
            /// Implements the write end of a self-pipe.
            /// Used to break out of the WaitForEvents.
            Pipe writePipe;
        #endif // !defined (TOOLCHAIN_OS_Windows)
            /// \brief
            /// Active stream list. Registry is also the stream owner.
            AsyncIoEventQueueRegistryList registryList;
            /// \brief
            /// Stream deletion has to be differed until it's safe.
            /// This list will hold zombie streams until it's safe
            /// to delete them (right before \see{WaitForEvents} returns).
            AsyncIoEventQueueDeletedStreamsList deletedStreamsList;
            /// \brief
            /// Synchronization SpinLock for registryList,
            /// timedStreamsList and deletedStreamsList.
            util::SpinLock spinLock;
            /// \brief
            /// Internal class used to help with Stream lifetime management.
            struct StreamDeleter;

        public:
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
            /// \brief
            /// Windows ctor.
            /// \param[in] concurrentThreads The maximum number
            /// of threads that the operating system can allow
            /// to concurrently process I/O completion packets
            /// for the I/O completion port.
            /// NOTE: All async io goes through the stream.
            /// \see{AsyncIoEventSink} will be called by the stream
            /// after it has determined what to call.
            AsyncIoEventQueue (
                util::ui32 concurrentThreads = DEFAULT_CONCURRENT_THREADS);
        #elif defined (TOOLCHAIN_OS_Linux)
            enum {
                /// \brief
                /// Default max queue size.
                DEFAULT_MAX_SIZE = 256
            };
            /// \brief
            /// Linux ctor.
            /// \param[in] maxSize Provided for completeness only.
            /// This parameter is ignored by epoll_create.
            explicit AsyncIoEventQueue (
                util::ui32 maxSize = DEFAULT_MAX_SIZE);
        #elif defined (TOOLCHAIN_OS_OSX)
            /// \brief
            /// OS X ctor.
            AsyncIoEventQueue ();
        #endif // defined (TOOLCHAIN_OS_Windows)
            /// \brief
            /// dtor. Close the queue handle.
            virtual ~AsyncIoEventQueue ();

            /// \brief
            /// Return the queue handle.
            /// \return Queue handle.
            inline THEKOGANS_UTIL_HANDLE GetHandle () const {
                return handle;
            }

            enum {
                /// \brief
                /// Default buffer length for async WSARecv[From | Msg].
                DEFAULT_BUFFER_LENGTH = 16384
            };

            /// \brief
            /// Add a given stream to the queue.
            /// \param[in] stream Stream to add.
            /// \param[in] eventSink \see{AsyncIoEventSink} that will
            /// receive the events.
            /// \param[in] bufferLength Buffer length for async
            /// WSARecv[From | Msg] and ReadFile on Windows.
            /// NOTE: For socket based async io, use the bufferLength
            /// parameter to select between max throughput and max
            /// connections. bufferLength == 0 reads will result in
            /// the ability to handle max connections. bufferLength != 0
            /// reads will result in max throughput (at the expense
            /// of locking system pages).
            /// VERY IMPORTANT: For (named) pipe io on Windows
            /// bufferLength cannot be == 0. Windows has no concept
            /// of zero length reads for these objects.
            void AddStream (
                Stream &stream,
                AsyncIoEventSink &eventSink,
                std::size_t bufferLength = DEFAULT_BUFFER_LENGTH);
            /// \brief
            /// Adds the given stream to the deletedStreams list.
            /// Streams are aggregated for deletion so as not to
            /// interfere with WaitForEvents. They get flushed as
            /// soon as WaitForEvents is done processing an event
            /// batch.
            /// \param[in] stream Stream to delete.
            void DeleteStream (Stream &stream);

            enum {
                /// \brief
                /// This is the default max events WaitForEvents
                /// will batch process at a time.
                DEFAULT_MAX_EVENTS_BATCH = 256
            };

            /// \brief
            /// Wait for and dispatch events.
            /// \param[in] maxEventsBatch Maximum events to batch
            /// process at a time.
            /// \param[in] timeSpec How long to wait for events.
            /// IMPORTANT: timeSpec is a relative value.
            void WaitForEvents (
                std::size_t maxEventsBatch = DEFAULT_MAX_EVENTS_BATCH,
                util::TimeSpec timeSpec = util::TimeSpec::Infinite);
            /// \brief
            /// Break out of the wait state.
            void Break ();

        private:
            /// \brief
            /// Flush the deleteStreams list.
            void ReleaseDeletedStreams ();

        #if !defined (TOOLCHAIN_OS_Windows)
            /// \brief
            /// Used internally by epoll and kqueue variants to
            /// add a 'stream is ready for events' notification.
            /// \param[in] stream Stream that wants to be notified
            /// when an event(s) it's interested in has occurred.
            /// \param[in] events A set of events the stream is
            /// interested in.
            void AddStreamForEvents (
                Stream &stream,
                util::ui32 events);
            /// \brief
            /// Used internally by epoll and kqueue variants to
            /// delete a 'stream is ready for events' notification.
            /// \param[in] stream Stream that wants to remove
            /// the 'stream is ready for events' notification.
            /// \param[in] events A set of events the stream is
            /// no longer interested in.
            void DeleteStreamForEvents (
                Stream &stream,
                util::ui32 events);
        #endif // !defined (TOOLCHAIN_OS_Windows)

            /// \brief
            /// \see{Stream::AsyncInfo} calls AddStreamForEvents,
            /// DeleteStreamForEvents (Linux/OS X) and UpdateTimedStream.
            friend struct Stream::AsyncInfo;
        #if defined (TOOLCHAIN_OS_Windows)
            /// \brief
            /// \see{Stream::AsyncInfo::Overlapped} calls AddTimedStream
            /// and DeleteTimedStream.
            friend struct Stream::AsyncInfo::Overlapped;
        #endif // defined (TOOLCHAIN_OS_Windows)

            /// \brief
            /// AsyncIoEventQueue is neither copy constructable, nor assignable.
            THEKOGANS_STREAM_DISALLOW_COPY_AND_ASSIGN (AsyncIoEventQueue)
        };

        /// \struct GlobalAsyncIoEventQueue AsyncIoEventQueue.h thekogans/stream/AsyncIoEventQueue.h
        ///
        /// \brief
        /// GlobalAsyncIoEventQueue follows the same design pattern as all the other global objects
        /// (See \see{thekogans::util::GlobalJobQueue}, \see{thekogans::util::GlobalJobQueuePool}...).
        /// It's job is to be a convenient global singleton for monitoring async streams. If you need
        /// multiple AsyncIoEventQueues, by all means use as many as you need. But if your needs are
        /// simple, GlobalAsyncIoEventQueue is here to help. The beauty of it's design is, if you never
        /// call thekogans::stream::GlobalAsyncIoEventQueue::Instance ().AddStream (...), it never gets
        /// created and does not consume any resources.
        /// NOTE: Because GlobalAsyncIoEventQueue is a global singleton that starts to run as soon
        /// as the first stream is added, calling \see{AsyncIoEventQueues::WaitForEvents} and
        /// \see{AsyncIoEventQueues::Break} on it is not appropriate.

        struct _LIB_THEKOGANS_STREAM_DECL GlobalAsyncIoEventQueue :
                public AsyncIoEventQueue,
                public util::Singleton<
                    GlobalAsyncIoEventQueue,
                    util::SpinLock,
                    util::RefCountedInstanceCreator<GlobalAsyncIoEventQueue>,
                    util::RefCountedInstanceDestroyer<GlobalAsyncIoEventQueue>>,
                public util::Thread {
            /// \brief
            /// ctor.
        #if defined (TOOLCHAIN_OS_Windows)
            /// \param[in] concurrentThreads The maximum number
            /// of threads that the operating system can allow
            /// to concurrently process I/O completion packets
            /// for the I/O completion port.
        #elif defined (TOOLCHAIN_OS_Linux)
            /// \param[in] maxSize Provided for completeness only.
        #endif // defined (TOOLCHAIN_OS_Windows)
            /// This parameter is ignored by epoll_create.
            /// \param[in] priority Thread priority.
            /// \param[in] affinity Thread affinity.
            GlobalAsyncIoEventQueue (
            #if defined (TOOLCHAIN_OS_Windows)
                util::ui32 concurrentThreads = AsyncIoEventQueue::DEFAULT_CONCURRENT_THREADS,
            #elif defined (TOOLCHAIN_OS_Linux)
                util::ui32 maxSize = AsyncIoEventQueue::DEFAULT_MAX_SIZE,
            #endif // defined (TOOLCHAIN_OS_Windows)
                util::i32 priority = THEKOGANS_UTIL_NORMAL_THREAD_PRIORITY,
                util::ui32 affinity = THEKOGANS_UTIL_MAX_THREAD_AFFINITY);

        private:
            // util::Thread
            /// \brief
            /// GlobalAsyncIoEventQueue thread.
            virtual void Run () throw ();

            /// \brief
            /// GlobalAsyncIoEventQueue is neither copy constructable nor assignable.
            THEKOGANS_STREAM_DISALLOW_COPY_AND_ASSIGN (GlobalAsyncIoEventQueue)
        };

    } // namespace stream
} // namespace thekogans

#endif // !defined (__thekogans_stream_AsyncIoEventQueue_h)
