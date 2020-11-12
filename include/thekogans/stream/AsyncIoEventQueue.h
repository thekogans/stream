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
        ///
        /// NOTE: AsyncIoEventQueue has full support for timed async
        /// streams. By calling Stream::Set[Read | Write]Timeout, you
        /// control how long a stream will wait for async io events
        /// before timing out. This feature has many uses, but one of
        /// the most important is controlling the lifetime of an async
        /// UDPSocket (especially SecureUDPSocket). Take a look at
        /// serverudpecho for an example on how to do that.

        struct _LIB_THEKOGANS_STREAM_DECL AsyncIoEventQueue : public util::ThreadSafeRefCounted {
            /// \brief
            /// Convenient typedef for util::ThreadSafeRefCounted::Ptr<AsyncIoEventQueue>.
            typedef util::ThreadSafeRefCounted::Ptr<AsyncIoEventQueue> Ptr;

            /// \struct AsyncIoEventQueue::TimeoutPolicy AsyncIoEventQueue.h
            /// thekogans/stream/AsyncIoEventQueue.h
            ///
            /// \brief
            /// For all the abstraction and encapsulation that thekogans_stream
            /// library provides, one of the things I am most proud of is that
            /// it provides this functionality at virtually zero cost. If you
            /// take a close look at the code, there are practically no for/while
            /// loops anywhere near the critical path. All this ends with timed
            /// async streams. In order to provide timed async stream support, I
            /// had to introduce a potentially very expensive O(n) operation in
            /// the heart of WaitForEvents (TimeoutTimedStreams). It's cost is
            /// derived not from it's complexity, but from the fact that streams
            /// are checked for timeout every time we process a batch of events.
            /// One can easily envision real world scenarios where this cost would
            /// be a huge burden on throughput. As a mater of fact, functionally,
            /// it is no different then the select system call. And we all know
            /// how well that scales (not well at all). This is where TimeoutPolicy
            /// comes in to play. This abstract class defines an interface for
            /// making runtime decisions about how often to check for timed out
            /// streams. It puts control in the hands of the system designer and
            /// architect to make the best choice for their particular situation.
            /// To go one step further, the choice doesn't have to be a static one.
            /// You can easily swap out policies based on runtime needs.
            struct _LIB_THEKOGANS_STREAM_DECL TimeoutPolicy : public util::ThreadSafeRefCounted {
                /// \brief
                /// Convenient typedef for util::ThreadSafeRefCounted::Ptr<TimeoutPolicy>.
                typedef util::ThreadSafeRefCounted::Ptr<TimeoutPolicy> Ptr;

                /// \brief
                /// dtor.
                virtual ~TimeoutPolicy () {}

                /// \brief
                /// Called by AsyncIoEventQueue::WaitForEvents to give the policy
                /// a chance to timeout streams. Given the stats gathering apis
                /// below, the only logic that should be executed here will look
                /// something like this:
                /// \code{.cpp}
                /// // okayToTimeout and nextCheckTimeSpec are calculated by
                /// // the stats gathering apis.
                /// if (okayToTimeout) {
                ///     eventQueue.TimeoutTimedStreams (timeSpec);
                /// }
                /// else if (timeSpec > nextCheckTimeSpec) {
                ///     timeSpec = nextCheckTimeSpec;
                /// }
                /// \endcode
                /// \param[in,out] timeSpec The TimeSpec passed to AsyncIoEventQueue::WaitForEvents.
                /// On return it should be adjusted to an interval to wait for io
                /// events before checking for timeouts again.
                virtual void TimeoutTimedStreams (util::TimeSpec & /*timeSpec*/) = 0;

                /// \brief
                /// The following three apis give the policy a chance to hook in to
                /// the event processing logic. Use them to gather advanced run-time
                /// stats to make informed decisions on when to best timeout timed
                /// streams.

                /// \brief
                /// Called by AsyncIoEventQueue::WaitForEvents before processing
                /// a batch of io events.
                /// \param[in] currentTime Current time.
                /// \param[in] countOfEvents Number of events in the batch.
                virtual void BeginEventBatch (
                    const util::TimeSpec & /*currentTime*/,
                    std::size_t /*countOfEvents*/) {}
                /// \brief
                /// Called by AsyncIoEventQueue::WaitForEvents after processing
                /// a batch of io events.
                /// \param[in] countOfTimedStreams Number of unique timed streams
                /// in the batch.
                /// \param[in] countOfRecentTimedStreams Number of unique streams
                /// that were seen in the previous event batch.
                /// TIP: Use countOfTimedStreams to estimate the amount of work
                /// done by timed streams in every event batch.
                /// Use countOfRecentTimedStreams to estimate the distribution
                /// of work among all timed streams.
                virtual void EndEventBatch (
                    std::size_t /*countOfTimedStreams*/,
                    std::size_t /*countOfRecentTimedStreams*/) {}
                /// \brief
                /// Called by AsyncIoEventQueue::WaitForEvents to give the policy
                /// a chance to gather run-time statistics. It's called for every
                /// timed stream in the event batch.
                /// \param[in] stream Timed stream that received an event.
                /// \param[in] event Event received by the timed stream.
                virtual void HandleTimedStream (
                    Stream & /*stream*/,
                    util::ui32 /*event*/) {}
            };

            /// \struct AsyncIoEventQueue::NullTimeoutPolicy AsyncIoEventQueue.h
            /// thekogans/stream/AsyncIoEventQueue.h
            ///
            /// \brief
            /// This policy is only suited for servers with no timed streams.
            /// It's the policy that's in force when AsyncIoEventQueue gets
            /// created. If you're going to handle timed streams, you need to
            /// replace it (SetTimeoutPolicy) with a policy appropriate for
            /// your design.
            struct _LIB_THEKOGANS_STREAM_DECL NullTimeoutPolicy : public TimeoutPolicy {
                /// \brief
                /// Noop.
                virtual void TimeoutTimedStreams (util::TimeSpec & /*timeSpec*/) {}
            };

            /// \struct AsyncIoEventQueue::DefaultTimeoutPolicy AsyncIoEventQueue.h
            /// thekogans/stream/AsyncIoEventQueue.h
            ///
            /// \brief
            /// This policy is best suited for servers with few active streams overall,
            /// and even fewer timed ones.
            struct _LIB_THEKOGANS_STREAM_DECL DefaultTimeoutPolicy : public TimeoutPolicy {
                /// \brief
                /// AsyncIoEventQueue this policy belongs to.
                AsyncIoEventQueue &eventQueue;

                /// \brief
                /// ctor.
                /// \param[in] eventQueue_ AsyncIoEventQueue this policy belongs to.
                explicit DefaultTimeoutPolicy (AsyncIoEventQueue &eventQueue_) :
                    eventQueue (eventQueue_) {}

                /// \brief
                /// Blindly calls AsyncIoEventQueue::TimeoutTimedStreams.
                virtual void TimeoutTimedStreams (util::TimeSpec &timeSpec) {
                    eventQueue.TimeoutTimedStreams (timeSpec);
                }
            };

        private:
            /// \brief
            /// Handle to an OS specific async io event queue.
            THEKOGANS_UTIL_HANDLE handle;
            /// \brief
            /// The timed stream timeout policy currently in force.
            TimeoutPolicy::Ptr timeoutPolicy;
            /// \brief
            /// Last io event batch time.
            util::TimeSpec lastEventBatchTime;
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
            /// Neither iocp nor epoll nor kqueue support timeouts
            /// for async streams. This list will hold streams that
            /// have Read/Write timeouts with corresponding operations
            /// in flight.
            AsyncIoEventQueueTimedStreamsList timedStreamsList;
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
            /// \brief
            /// Internal class used to help with timed Stream management.
            struct TimeoutPolicyController;

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
            /// Set the current timed stream timeout policy.
            /// \param[in] timeoutPolicy_ TimeoutPolicy to set.
            void SetTimeoutPolicy (TimeoutPolicy::Ptr timeoutPolicy_);

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
            /// Add a given stream to the timedStreams list.
            /// \param[in] stream Stream to add.
            void AddTimedStream (Stream &stream);
            /// \brief
            /// Delete a given stream from the timedStreams list.
            /// \param[in] stream Stream to delete.
            void DeleteTimedStream (Stream &stream);
            /// \brief
            /// Called after Stream::Set[Read | Write]Timeout to
            /// update the stream deadlines.
            /// \param[in] stream Stream to update.
            /// \param[in] events Events for which to check.
            /// \param[in] doBreak Call Break after updating.
            /// \return true = stream is timed, false = stream is not timed.
            bool UpdateTimedStream (
                Stream &stream,
                util::ui32 events,
                bool doBreak = true);
            /// \brief
            /// Walk the timedStreams list timing out expired streams.
            /// \param[in,out] timeSpec The TimeSpec passed to WaitForEvents.
            /// It will be adjusted to an interval to wait for io events
            /// before checking for timeouts again.
            /// \return Count of timed streams that timed out.
            std::size_t TimeoutTimedStreams (util::TimeSpec &timeSpec);

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
                public util::Singleton<GlobalAsyncIoEventQueue, util::SpinLock>,
                public util::Thread {
            /// \brief
            /// ctor.
            /// \param[in] concurrentThreads The maximum number
            /// of threads that the operating system can allow
            /// to concurrently process I/O completion packets
            /// for the I/O completion port.
            /// \param[in] maxSize Provided for completeness only.
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
            // util::ThreadSafeRefCounted
            /// \brief
            /// We're a singleton. We don't die.
            virtual void Harakiri () {}
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
