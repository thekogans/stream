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

#if !defined (__thekogans_stream_Stream_h)
#define __thekogans_stream_Stream_h

#include "thekogans/util/Environment.h"
#if !defined (TOOLCHAIN_OS_Windows)
    #include <list>
#endif // !defined (TOOLCHAIN_OS_Windows)
#include "thekogans/util/Types.h"
#include "thekogans/util/Heap.h"
#include "thekogans/util/RefCounted.h"
#include "thekogans/util/RefCountedRegistry.h"
#include "thekogans/util/Buffer.h"
#include "thekogans/util/SpinLock.h"
#include "thekogans/util/Exception.h"
#include "thekogans/util/Subscriber.h"
#include "thekogans/util/Producer.h"
#include "thekogans/stream/Config.h"
#include "thekogans/stream/Address.h"
#include "thekogans/stream/Overlapped.h"

namespace thekogans {
    namespace stream {

    #if !defined (TOOLCHAIN_OS_Windows)
        /// \brief
        /// Forward declaration of \see{AsyncIoEventQueue}.
        struct AsyncIoEventQueue;
    #endif // !defined (TOOLCHAIN_OS_Windows)
        /// \brief
        /// Forward declaration of \see{Stream}.
        struct Stream;

        /// \struct StreamEvents Stream.h thekogans/stream/Stream.h
        ///
        /// \brief
        /// Every \see{Stream} is able to fire the followig events. To receive a
        /// particular Stream's events you need to subscribe to its events.
        /// See \see{Pipe}, \see{NamedPipe}, \see{TCPSocket} and \see{UDPSocket}
        /// for examples on how to use that particular stream.
        /// NOTE: I chose to use \see{util::Buffer}::SharedPtr to notify the
        /// listeners when data was read (OnStreamRead) or written (OnStreamWrite).
        /// The reason for that is performance as copying buffers of data is
        /// expensive. The consequence of this decision is that all listeners get
        /// to see the same set of buffer read and write offsets. That can be
        /// problematic when trying to read the data from the buffer only to have
        /// a previous \see{util::Subscriber} modify these offsets. It is highly
        /// recommended that your own subscriber wrap the passed in buffer in a
        /// \see{util::TenantReadBuffer} to get its own set of offsets without
        /// disturbing the passed in buffer.

        struct _LIB_THEKOGANS_STREAM_DECL StreamEvents {
            /// \brief
            /// dtor.
            virtual ~StreamEvents () {}

            /// \brief
            /// Called to initiate stream error processing.
            /// \param[in] stream \see{Stream} on which an error occurred.
            /// \param[in] exception \see{util::Exception} representing the error.
            virtual void OnStreamError (
                util::RefCounted::SharedPtr<Stream> /*stream*/,
                const util::Exception & /*exception*/) noexcept {}

            /// \brief
            /// Called to initiate stream normal disconnect processing.
            /// \param[in] stream \see{Stream} that disconnected.
            virtual void OnStreamDisconnect (
                util::RefCounted::SharedPtr<Stream> /*stream*/) noexcept {}

            /// \brief
            /// Called when new data has arrived for the given stream.
            /// \param[in] stream \see{Stream} that received the data.
            /// \param[in] buffer The new data.
            virtual void OnStreamRead (
                util::RefCounted::SharedPtr<Stream> /*stream*/,
                util::Buffer::SharedPtr /*buffer*/) noexcept {}
            /// \brief
            /// Called when data was written to a stream.
            /// \param[in] stream Stream where data was written.
            /// \param[in] buffer The written data.
            virtual void OnStreamWrite (
                util::RefCounted::SharedPtr<Stream> /*stream*/,
                util::Buffer::SharedPtr /*buffer*/) noexcept {}
        };

        /// \struct Stream Stream.h thekogans/stream/Stream.h
        ///
        /// \brief
        /// Stream is an abstract base for all other stream types.
        /// It's main purpose is to expose the api a generic stream
        /// will have. Streams are reference counted. This makes it
        /// very easy to deal with lifetimes of async streams.
        ///
        /// NOTE: Stream anchors a handle based stream hierarchy.
        /// On Unix this is simple as everything is handle based (int).
        /// On Windows, not so much. Without going off on a rant, M$
        /// is a brain dead company which likes to employ brain dead
        /// engineers. The mess that is the WinSock API is pretty well
        /// understood, and I need not go in to it here. Suffice it to
        /// say that treating HANDLE (void *) and SOCKET (unsigned int *)
        /// as two distinct data types is beyond moronic. I absolutely
        /// hate to mix types, but these idiots left me no choice. It
        /// was either that, or a lot of code duplication.
        /// The only fortunate thing is that they in fact do declare
        /// INVALID_HANDLE_VALUE and INVALID_SOCKET to be the same
        /// underlying value (-1).
        ///
        /// Stream hierarchy:\n
        ///
        /// Stream\n
        ///   Pipe\n
        /// #if defined (TOOLCHAIN_OS_Windows)
        ///   NamedPipe\n
        /// #endif // defined (TOOLCHAIN_OS_Windows)
        ///   Socket\n
        ///     TCPSocket\n
        ///     UDPSocket\n

        struct _LIB_THEKOGANS_STREAM_DECL Stream : public util::Producer<StreamEvents> {
            /// \brief
            /// Declare \see{util::RefCounted} pointers.
            THEKOGANS_UTIL_DECLARE_REF_COUNTED_POINTERS (Stream)

            /// \brief
            /// Convenient typedef for util::RefCountedRegistry<Stream>.
            /// NOTE: It's one and only instance is accessed like this;
            /// thekogans::stream::Stream::Registry::Instance ().
            using Registry = util::RefCountedRegistry<Stream>;

        protected:
            /// \brief
            /// OS stream handle.
            THEKOGANS_UTIL_HANDLE handle;
            /// \brief
            /// This token is the key between the c++ and the c async io worlds (os).
            /// This token is registered with os specific apis (io completion port on
            /// windows, epoll on linux and kqueue on os x). On callback the token
            /// is used to get a Stream::SharedPtr from the Stream::WeakPtr found in
            /// the \see{Registry}.
            const Registry::Token token;
            /// \brief
            /// true == Automatically chain read requests.
            /// false == Manually post a new read request.
            /// NOTE: Under normal circumstances the default behavior (See \see{Overlapped})
            /// is desirable and the framework will take care of queuing up the next read
            /// request in the \see{Overlapped::Epilog}. If you need finer control over that
            /// set it to false and take care of queuing read requests yourself.
            /// IMPORTANT: Regardless of the state of chainRead, you're responsible for
            /// kick starting the process yourself (call initial Read/Accept. Look at
            /// \see{TCPSocket.h} for an example).
            bool chainRead;
        #if !defined (TOOLCHAIN_OS_Windows)
            /// \brief
            /// Outstanding read requests.
            Overlapped::Queue in;
            /// \brief
            /// Outstanding write requests.
            Overlapped::Queue out;
            /// \brief
            /// Lock serializing access to in and out.
            util::SpinLock spinLock;
        #endif // !defined (TOOLCHAIN_OS_Windows)

        public:
            /// \brief
            /// ctor.
            /// \param[in] handle_ OS stream handle.
            /// NOTE: Stream wraps the handle and takes ownership of it's lifetime.
            /// The handle will be closed when the stream dtor is called.
            explicit Stream (THEKOGANS_UTIL_HANDLE handle_);
            /// \brief
            /// dtor.
            virtual ~Stream ();

            /// \brief
            /// Use this method if you need framework interoperability.
            /// IMPORTANT: Stream owns the handle and will close it in it's dtor.
            /// \return Native OS stream handle.
            inline THEKOGANS_UTIL_HANDLE GetHandle () const {
                return handle;
            }

            /// \brief
            /// Return true if various ReadOverlapped should chain the
            /// following read after the current one finishes.
            /// \return true == chain following read.
            inline bool IsChainRead () const {
                return chainRead;
            }
            /// \brief
            /// Set chainRead.
            /// \param[in] chainRead_ New chainRead value.
            inline void SetChainRead (bool chainRead_) {
                chainRead = chainRead_;
            }

            /// \brief
            /// Close the OS handle associated with the stream.
            /// NOTE: Close does not throw. It's end state is an invalid
            /// handle regardless if we closed the actual handle.
            virtual void Close () noexcept;

            /// \brief
            /// Default buffer length for async Read[From | Msg].
            static const std::size_t DEFAULT_BUFFER_LENGTH = 16384;
            /// \brief
            /// Async read bytes from the stream.
            /// \param[in] bufferLength Number of bytes to read (For \see{TCPSocket} this
            /// number can and should be 0. This way you will get everything that has arrived).
            /// IMPORTANT: bufferLength specifies the max number of bytes that
            /// will be returned by this read. If there are fewer bytes available
            /// then requested, then fewer will be returned. If chainRead == true, the
            /// \ss{Overlapped} responsible for this read will queue up a new async read
            /// request before returning the bytes. If chainRead == false, it's up to the
            /// caller to continue calling Read (in OnStreamRead?) to get more bytes.
            virtual void Read (std::size_t /*bufferLength*/ = DEFAULT_BUFFER_LENGTH) = 0;
            /// \brief
            /// Async write \see{util::Buffer} to the stream. This method is more
            /// efficient than writing bytes (below) as there's no copy overhead.
            /// \param[in] buffer Buffer to write.
            virtual void Write (util::Buffer::SharedPtr /*buffer*/) = 0;
            /// \brief
            /// Async write bytes to the stream. Upon return this method will have made
            /// a copy of the buffer contents and it can be deleted by the caller without
            /// waiting for the async write to complete.
            /// \param[in] buffer Bytes to write.
            /// \param[in] bufferLength Buffer length.
            void Write (
                const void *buffer,
                std::size_t bufferLength);

        protected:
        #if !defined (TOOLCHAIN_OS_Windows)
            /// \brief
            /// Enqueue the given \see{Overlapped} on the given \see{Overlapped::Queue}.
            /// This is a 'user' facing API. If you derive from stream and your custom
            /// stream needs it's own \see{Overlapped} type. This is the method you call
            /// to queue it up.
            /// \param[in] overlapped \see{Overlapped} to enqueue.
            /// \param[in] queue \see{Overlapped::Queue} to enqueue the given \see{Overlapped} on.
            void EnqOverlapped (
                Overlapped::SharedPtr overlapped,
                Overlapped::Queue &queue) noexcept;

            /// \brief
            /// Called by \see{AsyncIoEventQueue} to remove the head \see{Overlapped}
            /// from the given queue.
            /// The following two methods are part of the back end async machinery
            /// burried inside \see{AsyncIoEventQueue}. Together with Enqoverlapped
            /// above they form the overalapped interface we emulate from Windows.
            /// \param[in] queue Queue to remove the head \see{Overlapped} from.
            void DeqOverlapped (Overlapped::Queue &queue) noexcept;

            /// \brief
            /// Called by \see{AsyncIoEventQueue} to retrieve the head \see{Overlapped}
            /// from the given queue.
            /// \param[in] queue Queue to retrieve the head \see{Overlapped} from.
            /// \return Pointer to the head \see{Overlapped}.
            /// \see{Overlapped}::SharedPtr if queue.empty () == true.
            Overlapped::SharedPtr HeadOverlapped (Overlapped::Queue &queue) noexcept;

            /// \brief
            /// \see{AsyncIoEventQueue} needs access to private members.
            friend struct AsyncIoEventQueue;
        #endif // !defined (TOOLCHAIN_OS_Windows)

            /// \brief
            /// Stream is neither copy constructable, nor assignable.
            THEKOGANS_UTIL_DISALLOW_COPY_AND_ASSIGN (Stream)
        };

        /// \def THEKOGANS_STREAM_DECLARE_STREAM(_T)
        /// This macro is used in a stream declaration file (.h).
        /// \param[in] _T Stream class name.
        #define THEKOGANS_STREAM_DECLARE_STREAM(_T)\
            THEKOGANS_UTIL_DECLARE_STD_ALLOCATOR_FUNCTIONS\
            THEKOGANS_UTIL_DECLARE_REF_COUNTED_POINTERS (_T)\
            THEKOGANS_UTIL_DISALLOW_COPY_AND_ASSIGN (_T)

        /// \def THEKOGANS_STREAM_IMPLEMENT_STREAM(_T)
        /// This macro is used in the stream definition file (.cpp).
        /// \param[in] _T Stream class name.
        #define THEKOGANS_STREAM_IMPLEMENT_STREAM(_T)\
            THEKOGANS_UTIL_IMPLEMENT_HEAP_FUNCTIONS (_T)

    } // namespace stream
} // namespace thekogans

#endif // !defined (__thekogans_stream_Stream_h)
