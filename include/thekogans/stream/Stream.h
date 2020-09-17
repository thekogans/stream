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

#include <memory>
#include <utility>
#include <string>
#include <map>
#include "pugixml/pugixml.hpp"
#include "thekogans/util/Types.h"
#include "thekogans/util/Constants.h"
#include "thekogans/util/Heap.h"
#include "thekogans/util/RefCounted.h"
#include "thekogans/util/IntrusiveList.h"
#include "thekogans/util/Buffer.h"
#include "thekogans/util/SpinLock.h"
#include "thekogans/util/Exception.h"
#include "thekogans/util/LoggerMgr.h"
#include "thekogans/stream/Config.h"
#include "thekogans/stream/Address.h"
#include "thekogans/stream/MsgHdr.h"

namespace thekogans {
    namespace stream {

        /// \brief
        /// Forward declaration of \see{StreamSelector}.
        struct StreamSelector;
        /// \brief
        /// Forward declaration of \see{AsyncIoEventQueue}.
        struct AsyncIoEventQueue;
        /// \brief
        /// Forward declaration of \see{AsyncIoEventSink}.
        struct AsyncIoEventSink;
        /// \brief
        /// Forward declaration of Stream.
        struct Stream;

        enum {
            /// \brief
            /// AsyncIoEventQueueRegistryList list id.
            ASYNC_IO_EVENT_QUEUE_REGISTRY_LIST_ID,
            /// \brief
            /// AsyncIoEventQueueTimedStreamsList list id.
            ASYNC_IO_EVENT_QUEUE_TIMED_STREAMS_LIST_ID,
        };

        /// \brief
        /// Convenient typedef for util::IntrusiveList<Stream, ASYNC_IO_EVENT_QUEUE_REGISTRY_LIST_ID>.
        typedef util::IntrusiveList<Stream, ASYNC_IO_EVENT_QUEUE_REGISTRY_LIST_ID>
            AsyncIoEventQueueRegistryList;
        /// \brief
        /// Convenient typedef for util::IntrusiveList<Stream, ASYNC_IO_EVENT_QUEUE_TIMED_STREAMS_LIST_ID>.
        typedef util::IntrusiveList<Stream, ASYNC_IO_EVENT_QUEUE_TIMED_STREAMS_LIST_ID>
            AsyncIoEventQueueTimedStreamsList;

        // Did I mention M$ is a brain dead company? Here's another
        // example of their stupidity and the hoops we have to jump
        // through to get around the obstacles they throw our way.
    #if defined (_MSC_VER)
        #pragma warning (push)
        #pragma warning (disable : 4275)
    #endif // defined (_MSC_VER)

        /// \struct Stream Stream.h thekogans/stream/Stream.h
        ///
        /// \brief
        /// Stream is an abstract base for all other stream types.
        /// It's main purpose is to house Context/AsyncInfo as well
        /// as expose the api a generic stream will have. Streams are
        /// reference counted. This makes it very easy to deal with
        /// lifetimes of async streams (especially on Windows).
        /// Because of the design of \see{util::RefCounted}, creating
        /// a stream on the stack is as simple as declaring it. No
        /// allocation/deallocation necessary.
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
        ///     ClientNamedPipe\n
        ///     ServerNamedPipe\n
        /// #endif // defined (TOOLCHAIN_OS_Windows)
        ///   Socket\n
        ///     TCPSocket\n
        ///       ClientTCPSocket\n
        ///       ServerTCPSocket\n
        ///       SecureTCPSocket\n
        ///         ClientSecureTCPSocket\n
        ///       ServerSecureTCPSocket\n
        ///     UDPSocket\n
        ///       ClientUDPSocket\n
        ///       ServerUDPSocket\n
        ///       SecureUDPSocket\n
        ///         ClientSecureUDPSocket\n
        ///       ServerSecureUDPSocket\n

        struct _LIB_THEKOGANS_STREAM_DECL Stream :
                public virtual util::ThreadSafeRefCounted,
                public AsyncIoEventQueueRegistryList::Node,
                public AsyncIoEventQueueTimedStreamsList::Node {
            /// \brief
            /// Convenient typedef for util::ThreadSafeRefCounted::Ptr<Stream>.
            typedef util::ThreadSafeRefCounted::Ptr<Stream> Ptr;

            /// \struct Stream::Context Stream.h thekogans/stream/Stream.h
            ///
            /// \brief
            /// Context implements a memento pattern. It records all
            /// the details necessary to reconstitute a stream from rest.
            /// Use Context::ToString to create an XML representation
            /// suitable for storage. Later you can use Stream::GetContext
            /// to recreate it. From there, you can call Context::CreateStream
            /// to create a fully initialized stream from the parameters.
            struct _LIB_THEKOGANS_STREAM_DECL Context : public util::ThreadSafeRefCounted {
                /// \brief
                /// Convenient typedef for <Context>.
                typedef util::ThreadSafeRefCounted::Ptr<Context> Ptr;

                /// \brief
                /// "Context"
                static const char * const TAG_CONTEXT;
                /// \brief
                /// "Type"
                static const char * const ATTR_TYPE;

                /// \brief
                /// Stream type (it's class name).
                std::string type;

                /// \brief
                /// ctor.
                Context () {}
                /// \brief
                /// ctor.
                /// param[in] type_ Type this Context represents.
                explicit Context (const std::string type_) :
                    type (type_) {}
                /// \brief
                /// dtor.
                virtual ~Context () {}

                /// \brief
                /// Parse the Context parameters from the given node.
                /// \param[in] node Node that represents the Context.
                virtual void Parse (const pugi::xml_node & /*node*/) = 0;
                /// \brief
                /// Serialize the Context parameters in to an XML string.
                /// \param[in] indentationLevel Pretty print parameter. If
                /// the resulting tag is to be included in a larger structure
                /// you might want to provide a value that will indent it in
                /// the structure.
                /// \param[in] tagName Name of the containing tag.
                /// \return The XML reprentation of the Context.
                virtual std::string ToString (
                    std::size_t /*indentationLevel*/ = 0,
                    const char * /*tagName*/ = TAG_CONTEXT) const = 0;

                /// \brief
                /// Create a stream from the Context parameters.
                /// \return The newly created stream.
                virtual Stream::Ptr CreateStream () const = 0;
            };

        protected:
            /// \brief
            /// Typedef for Context factory method. A method of this type will
            /// create a correct Context from the values found in the XML node.
            /// \param[in] node XML node that will contain the Context.
            typedef Context::Ptr (*ContextFactory) (const pugi::xml_node &node);
            /// \brief
            /// Typedef for an Context/Stream factories map. This map
            /// is populated at initialization time by the MapInitializer
            /// below, and is used at run time to create dynamic streams.
            typedef std::map<std::string, ContextFactory> Map;
            /// \brief
            /// Return a reference to a properly constructed map.
            /// This accessor is here to make sure that std::map
            /// constructor gets called correctly.
            /// \return &map.
            static Map &GetMap ();

            /// \struct Stream::MapInitializer Stream.h thekogans/stream/Stream.h
            ///
            /// \brief
            /// MapInitializer is used to initialize the Stream::map.
            /// It should not be used directly, and instead is included
            /// in THEKOGANS_STREAM_DECLARE_STREAM/THEKOGANS_STREAM_IMPLEMENT_STREAM.
            /// If you're deriving a stream from Stream, and you want
            /// it to be dynamically discoverable/creatable, add
            /// THEKOGANS_STREAM_DECLARE_STREAM to it's declaration,
            /// and THEKOGANS_STREAM_IMPLEMENT_STREAM to it's definition.
            struct _LIB_THEKOGANS_STREAM_DECL MapInitializer {
                /// \brief
                /// ctor. Add stream of type and factory for creating it's
                /// Context to the Stream::map.
                /// \param[in] type Stream type (it's class name).
                /// \param[in] contextFactory Context creation factory.
                MapInitializer (
                    const std::string &type,
                    ContextFactory contextFactory);
            };

            /// \brief
            /// Stream handle.
            THEKOGANS_UTIL_HANDLE handle;

        public:
            /// \brief
            /// ctor.
            /// Wrap an OS handle.
            /// \param[in] handle_ OS stream handle to wrap.
            Stream (THEKOGANS_UTIL_HANDLE handle_ = THEKOGANS_UTIL_INVALID_HANDLE_VALUE) :
                handle (handle_) {}
            /// \brief
            /// dtor.
            virtual ~Stream ();

            /// \brief
            /// Given an XML node representing an Context, return
            /// a fully parsed and populated Context of that specific
            /// type.
            /// \param[in] node XML node representing an Context of a particular type.
            /// \return A fully parsed and populated Context of that type.
            static Context::Ptr GetContext (const pugi::xml_node &node);
        #if defined (THEKOGANS_STREAM_TYPE_Static)
            /// \brief
            /// Because the stream library uses dynamic initialization,
            /// when using it in static builds call this method to have
            /// the library explicitly include all internal stream types.
            /// Without calling this api, the only streams that will be
            /// available to your application are the ones you explicitly
            /// link to.
            static void StaticInit ();
        #endif // defined (THEKOGANS_STREAM_TYPE_Static)

            /// \brief
            /// Check if stream has a valid handle.
            /// \return true = yes, false = no.
            inline bool IsOpen () const {
                return handle != THEKOGANS_UTIL_INVALID_HANDLE_VALUE;
            }

            /// \brief
            /// Check if stream is async (\see{AsyncIoEventQueue::AddStream}
            /// was called on the stream).
            /// \return true = async, false = blocking.
            inline bool IsAsync () const {
                return asyncInfo.Get () != 0;
            }
            /// \brief
            /// Chain unimplemented callbacks to the given handler.
            /// \param[in] next Handler to be called for all unimplemented callbacks.
            void ChainAsyncIoEventSink (AsyncIoEventSink &next);

            /// \brief
            /// Use this method if you need framework interoperability.
            /// IMPORTANT: Stream owns the handle and will close it in it's dtor.
            /// \return Native OS stream handle.
            inline THEKOGANS_UTIL_HANDLE GetHandle () const {
                return handle;
            }
            /// \brief
            /// Use this method if you need framework interoperability.
            /// IMPORTANT: You now own the handle and it's lifetime.
            /// \return Native OS stream handle.
            inline THEKOGANS_UTIL_HANDLE ReleaseHandle () {
                return util::EXCHANGE (handle, THEKOGANS_UTIL_INVALID_HANDLE_VALUE);
            }

            /// \brief
            /// Disconnect the stream from it's peer.
            virtual void Disconnect ();

            /// \brief
            /// Read bytes from the stream.
            /// \param[out] buffer Where to place the bytes.
            /// \param[in] count Buffer length.
            /// \return Count of bytes actually placed in the buffer.
            /// NOTE: This api is to be called by blocking streams only.
            /// An async stream will listen for incoming data, and notify
            /// \see{AsyncIoEventSink::HandleStreamRead}.
            virtual std::size_t Read (
                void * /*buffer*/,
                std::size_t /*count*/) = 0;
            /// \brief
            /// Write bytes to the stream.
            /// \param[in] buffer Bytes to write.
            /// \param[in] count Buffer length.
            /// \return Count of bytes actually written.
            /// NOTE: Blocking streams may or may not be able to write
            /// an entire buffer all in one shot. Use the return value
            /// to tell how many bytes were actually written. This is
            /// why WriteFullBuffer (const void *, std::size_t) below
            /// exists. Async streams will write the entire buffer,
            /// and will notify \see{AsyncIoEventSink::HandleStreamWrite}
            /// when they are done.
            virtual std::size_t Write (
                const void * /*buffer*/,
                std::size_t /*count*/) = 0;

            /// \brief
            /// Async write a buffer to the stream. This function is a
            /// mirror image of WriteFullBuffer (const void *, std::size_t).
            /// It is meant to be used with async streams only. The reason
            /// this function is not supported with synchronous streams
            /// is the util::Buffer parameter. A synchronous
            /// stream might only write a part of the buffer, but if we
            /// don't take ownership it will be gone when we return. The
            /// only way we can take ownership is if we're asynchronous.
            /// NOTE: The rational behind this function is: Async
            /// Write (const void *, std::size_t) has no way of knowing
            /// where it's parameters come from. To place a burden on
            /// the user, and have her hold on to the const void *buffer
            /// until the async Write completes is not acceptable. Async
            /// Write (const void *, std::size_t) does the only logical
            /// thing left for it to do, it makes a copy of the supplied
            /// const void *buffer. As you can imagine that can be very
            /// wasteful, and inefficient. To add insult to injury, if
            /// the supplied buffer came from util::Buffer, which is
            /// quite capable of managing it's own lifetime, the copy
            /// penalty is paid for nothing. This is where this api shines.
            /// It takes ownership of the util::Buffer buffer and no
            /// copy is necessary.
            /// VERY IMPORTANT: Write will start writing at buffer->readOffset!
            /// This is a very important design element. It allows you to
            /// build the buffer piecemeal, and write new data periodically.
            /// To do that, the util::Buffer you pass to WriteBuffer cannot
            /// be the owner of the data. You need to use the following
            /// technique:
            /// \code{.cpp}
            /// using namespace thekogans;
            /// // Create the owning buffer.
            /// util::Buffer buffer (util::NetworkEndian, ...);
            /// do {
            ///     // Fill a portion of the buffer.
            ///     ...
            ///     // Send that portion to a stream for writing.
            ///     stream->WriteBuffer (
            ///         util::TenantReadBuffer (
            ///             buffer.endianness,
            ///             buffer.GetReadPtr (),
            ///             buffer.GetDataAvailableForReading ());
            ///     // Continue filling and sending a portion of the owning
            ///     // buffer until done.
            ///     // NOTE: This technique assumes that you're correctly
            ///     // maintaining the buffer.writeOffset. If you're using
            ///     // the various Buffer insertion operators, this is
            ///     // done for you automatically.
            /// } while (...);
            /// // VERY, VERY IMPORTANT: The owning buffer created above
            /// // must survive until every async operation based on it
            /// // completes. That's because every TenantReadBuffer
            /// // sent to WriteBuffer points in to it's data member.
            /// \endcode
            /// \param[in] buffer Buffer to write.
            virtual void WriteBuffer (util::Buffer /*buffer*/) = 0;

            /// \brief
            /// Don't return until count of bytes is read.
            /// This api is only useful for blocking streams, as
            /// async streams will always read in chunks.
            /// \param[in] buffer Where to place the bytes.
            /// \param[in] count Buffer length.
            void ReadFullBuffer (
                void *buffer,
                std::size_t count);

            /// \brief
            /// Don't return until count of bytes is written.
            /// This api is only useful for blocking streams, as
            /// async streams will always write full buffers.
            /// \param[in] buffer Bytes to write.
            /// \param[in] count Buffer length.
            void WriteFullBuffer (
                const void *buffer,
                std::size_t count);

            /// \brief
            /// Return the read timeout value.
            /// \return The read timeout value.
            virtual util::TimeSpec GetReadTimeout () const = 0;
            /// \brief
            /// Set the read timeout. util::TimeSpec::Zero == no timeout.
            /// \param[in] timeSpec Read timeout.
            virtual void SetReadTimeout (const util::TimeSpec & /*timeSpec*/) = 0;

            /// \brief
            /// Return the write timeout value.
            /// \return The write timeout value.
            virtual util::TimeSpec GetWriteTimeout () const = 0;
            /// \brief
            /// Set the write timeout. util::TimeSpec::Zero == no timeout.
            /// \param[in] timeSpec Write timeout.
            virtual void SetWriteTimeout (const util::TimeSpec & /*timeSpec*/) = 0;

        protected:
            /// \brief
            /// Close the stream.
            virtual void Close ();

            /// \struct Stream::AsyncInfo Stream.h thekogans/stream/Stream.h
            ///
            /// \brief
            /// AsyncInfo holds the async state and is created when you
            /// call \see{AsyncIoEventQueue::AddStream}.
            struct _LIB_THEKOGANS_STREAM_DECL AsyncInfo : public util::ThreadSafeRefCounted {
                /// \brief
                /// Convenient typedef for util::ThreadSafeRefCounted::Ptr<AsyncInfo>.
                typedef util::ThreadSafeRefCounted::Ptr<AsyncInfo> Ptr;

                /// \brief
                /// AsyncInfo has a private heap to help with memory
                /// management, performance, and global heap fragmentation.
                THEKOGANS_UTIL_DECLARE_HEAP_WITH_LOCK (AsyncInfo, util::SpinLock)

                /// \enum
                /// Event types.
                enum {
                    /// \brief
                    /// Invalid event.
                    EventInvalid = 0,
                    /// \brief
                    /// Stream has connected to the peer (\see{TCPSocket} and friends).
                    /// Or a connection has arrived on \see{ServerTCPSocket} or
                    /// \see{ServerSecureTCPSocket}.
                    EventConnect = 1,
                    /// \brief
                    /// Stream has been disconnected
                    /// from by the peer (\see{TCPSocket} and friends).
                    EventDisconnect = 2,
                    /// \brief
                    /// Stream has been shutdown
                    /// from by the peer (\see{TCPSocket} and friends).
                    EventShutdown = 4,
                    /// \brief
                    /// Data is available for reading.
                    EventRead = 8,
                    /// \brief
                    /// Stream is ready for writing.
                    EventWrite = 16,
                    /// \brief
                    /// Data is available for reading.
                    EventReadFrom = 32,
                    /// \brief
                    /// Stream is ready for writing.
                    EventWriteTo = 64,
                    /// \brief
                    /// Data is available for reading.
                    EventReadMsg = 128,
                    /// \brief
                    /// Stream is ready for writing.
                    EventWriteMsg = 256
                };

                /// \brief
                /// "EventInvalid"
                static const char * const EVENT_INVALID;
                /// \brief
                /// "EventConnect"
                static const char * const EVENT_CONNECT;
                /// \brief
                /// "EventDisconnect"
                static const char * const EVENT_DISCONNECT;
                /// \brief
                /// "EventShutdown"
                static const char * const EVENT_SHUTDOWN;
                /// \brief
                /// "EventRead"
                static const char * const EVENT_READ;
                /// \brief
                /// "EventWrite"
                static const char * const EVENT_WRITE;
                /// \brief
                /// "EventReadFrom"
                static const char * const EVENT_READ_FROM;
                /// \brief
                /// "EventWriteTo"
                static const char * const EVENT_WRITE_TO;
                /// \brief
                /// "EventReadMsg"
                static const char * const EVENT_READ_MSG;
                /// \brief
                /// "EventWriteMsg"
                static const char * const EVENT_WRITE_MSG;

                /// \brief
                /// Convert event to it's string equivalent.
                /// \param[in] event Stream::AsyncInfo event.
                /// \return String equivalent of event.
                static std::string eventToString (util::ui32 event);
                /// \brief
                /// Convert string form of event in to Stream::AsyncInfo event.
                /// \param[in] event String equivalent of event.
                /// \return Stream::AsyncInfo event.
                static util::ui32 stringToEvent (const std::string &event);

                /// \brief
                /// The AsyncIoEventQueue this stream is associated with.
                AsyncIoEventQueue &eventQueue;
                /// \brief
                /// The Stream this AsyncInfo belongs to.
                Stream &stream;
                /// \brief
                /// The \see{AsyncIoEventSink} that will receive notifications.
                AsyncIoEventSink &eventSink;
                /// \brief
                /// Buffer length for async WSARecv[From | Msg].
                std::size_t bufferLength;
            #if defined (TOOLCHAIN_OS_Windows)
                /// \brief
                /// Forward declaration of Overlapped.
                struct Overlapped;
                enum {
                    /// \brief
                    /// OverlappedList ID.
                    OVERLAPPED_LIST_ID
                };
                /// \brief
                /// Convenient typedef for util::IntrusiveList<Overlapped, OVERLAPPED_LIST_ID>.
                typedef util::IntrusiveList<Overlapped, OVERLAPPED_LIST_ID> OverlappedList;
                /// \struct Stream::AsyncInfo::Overlapped Stream.h thekogans/stream/Stream.h
                ///
                /// \brief
                /// Overlapped extends a Windows WSAOVERLAPPED.
                struct Overlapped :
                        public WSAOVERLAPPED,
                        public OverlappedList::Node,
                        public util::ThreadSafeRefCounted {
                    /// \brief
                    /// Convenient typedef for util::ThreadSafeRefCounted::Ptr<Overlapped>.
                    typedef util::ThreadSafeRefCounted::Ptr<Overlapped> Ptr;

                    /// \brief
                    /// Stream that created this Overlapped.
                    Stream::Ptr stream;
                    /// \brief
                    /// Operation represented by this Overlapped.
                    util::ui32 event;
                    /// \brief
                    /// Absolute timeout value for timed async io.
                    util::TimeSpec deadline;

                    /// \brief
                    /// ctor.
                    /// \param[in] stream_ Stream that created this Overlapped.
                    /// \param[in] event_ Operation being performed by this Overlapped.
                    Overlapped (
                        Stream &stream_,
                        util::ui32 event_);
                    /// \brief
                    /// dtor.
                    virtual ~Overlapped ();

                    /// \brief
                    /// Return error code.
                    /// \return Error code.
                    inline THEKOGANS_UTIL_ERROR_CODE GetError () const {
                        return (THEKOGANS_UTIL_ERROR_CODE)Internal;
                    }
                    /// \brief
                    /// Set error code.
                    /// \param[in] error Error code.
                    inline void SetError (THEKOGANS_UTIL_ERROR_CODE error) {
                        Internal = (ULONG_PTR)error;
                    }

                    /// \brief
                    /// Return count of bytes read or written.
                    /// \return Count of bytes read or written.
                    inline DWORD GetCount () const {
                        return (DWORD)InternalHigh;
                    }
                    /// \brief
                    /// Set count of bytes read or written.
                    /// \param[in] count Count of bytes read or written.
                    inline void SetCount (DWORD count) {
                        InternalHigh = (ULONG_PTR)count;
                    }

                    /// \brief
                    /// Return offset in the stream where bytes are read or written.
                    /// \return Offset in the stream where bytes are read or written.
                    util::ui64 GetOffset () const;
                    /// \brief
                    /// Set offset in the stream where bytes are read or written.
                    /// \param[in] offset_ Offset in the stream where bytes are read or written.
                    void SetOffset (util::ui64 offset_);

                    /// \brief
                    /// Return true if the operation represented by this overlapped timed out.
                    /// \param[in] currentTime Current time.
                    /// \return true if the operation represented by this overlapped timed out.
                    inline bool TimedOut (const util::TimeSpec &currentTime) const {
                        return deadline != util::TimeSpec::Zero && currentTime >= deadline;
                    }

                    /// \brief
                    /// Called by \see{AsyncIoEventQueue::WaitForEvents} to allow
                    /// the Overlapped to perform post op housekeeping prior to calling
                    /// GetError.
                    virtual void Prolog () throw () {}
                    /// \brief
                    /// Called by \see{AsyncIoEventQueue::WaitForEvents} to allow
                    /// the Overlapped to perform post op housekeeping after calling
                    /// GetError.
                    /// NOTE: Epiplog will not be called if GetError returns with
                    /// anything other then ERROR_SUCCESS.
                    virtual void Epilog () throw () {}

                    /// \brief
                    /// Overlapped is neither copy constructable, nor assignable.
                    THEKOGANS_STREAM_DISALLOW_COPY_AND_ASSIGN (Overlapped)
                };
                /// \struct Stream::AsyncInfo::ReadWrietOverlapped Stream.h thekogans/stream/Stream.h
                ///
                /// \brief
                /// ReadWriteOverlapped is a helper class. It reduces code clutter and
                /// makes instantiating Overlapped used by \see{Stream::Read} and
                /// \see{Stream::Write} easier.
                struct ReadWriteOverlapped : public Overlapped {
                    /// \brief
                    /// Convenient typedef for util::ThreadSafeRefCounted::Ptr<ReadWriteOverlapped>.
                    typedef util::ThreadSafeRefCounted::Ptr<ReadWriteOverlapped> Ptr;

                    /// \brief
                    /// ReadWriteOverlapped has a private heap to help with memory
                    /// management, performance, and global heap fragmentation.
                    THEKOGANS_UTIL_DECLARE_HEAP_WITH_LOCK (ReadWriteOverlapped, util::SpinLock)

                    /// \brief
                    /// Buffer used by Stream::Read/Write.
                    util::Buffer buffer;
                    /// \brief
                    /// WSARecv/Send buffer.
                    WSABUF wsaBuf;
                    /// \brief
                    /// WSARecv/Send flags.
                    DWORD flags;

                    /// \brief
                    /// ctor.
                    /// \param[in] stream Stream that created this ReadOverlapped.
                    /// \param[in] count Length of buffer to allocate for reading.
                    /// \param[in] useGetBuffer If true, call \see{AsyncIoEventSink::GetBuffer}
                    ReadWriteOverlapped (
                        Stream &stream,
                        std::size_t count,
                        bool useGetBuffer = true);
                    /// \brief
                    /// ctor.
                    /// \param[in] stream Stream that created this WriteOverlapped.
                    /// \param[in] buffer_ Buffer to write.
                    /// \param[in] count Lenght of buffer.
                    /// \param[in] useGetBuffer If true, call \see{AsyncIoEventSink::GetBuffer}
                    ReadWriteOverlapped (
                        Stream &stream,
                        const void *buffer_,
                        std::size_t count,
                        bool useGetBuffer = true);
                    /// \brief
                    /// ctor.
                    /// \param[in] stream Stream that created this WriteOverlapped.
                    /// \param[in] buffer Buffer to write.
                    ReadWriteOverlapped (
                            Stream &stream,
                            util::Buffer buffer_) :
                            Overlapped (stream, Stream::AsyncInfo::EventWrite),
                            buffer (std::move (buffer_)),
                            flags (0) {
                        wsaBuf.len = (ULONG)buffer.GetDataAvailableForReading ();
                        wsaBuf.buf = (char *)buffer.GetReadPtr ();
                    }

                    /// \brief
                    /// Called by \see{AsyncIoEventQueue::WaitForEvents} to allow
                    /// the ReadWriteOverlapped to perform post op housekeeping.
                    virtual void Epilog () throw ();

                    /// \brief
                    /// ReadWriteOverlapped is neither copy constructable, nor assignable.
                    THEKOGANS_STREAM_DISALLOW_COPY_AND_ASSIGN (ReadWriteOverlapped)
                };
                /// \brief
                /// Outstanding overlapped io.
                OverlappedList overlappedList;
            #else // defined (TOOLCHAIN_OS_Windows)
                /// \brief
                /// Events mask that records the events this
                /// stream is interested in.
                util::ui32 events;
                /// \brief
                /// Forward declaration of BufferInfo.
                struct BufferInfo;
                enum {
                    /// \brief
                    /// BufferInfoList ID.
                    BUFFER_INFO_LIST_ID
                };
                /// \brief
                /// Convenient typedef for util::IntrusiveList<BufferInfo, BUFFER_INFO_LIST_ID>.
                typedef util::IntrusiveList<BufferInfo, BUFFER_INFO_LIST_ID> BufferInfoList;
                /// \struct Stream::AsyncInfo::BufferInfo Stream.h thekogans/stream/Stream.h
                ///
                /// \brief
                /// BufferInfo is a virtual base for buffers used for async
                /// Stream::Write. Various derivatives represent concrete
                /// BufferInfo for Write, WriteTo and WriteMsg.
                struct BufferInfo :
                        public BufferInfoList::Node,
                        public util::ThreadSafeRefCounted {
                    /// \brief
                    /// Convenient typedef for util::ThreadSafeRefCounted::Ptr<BufferInfo>.
                    typedef util::ThreadSafeRefCounted::Ptr<BufferInfo> Ptr;

                    /// \brief
                    /// Stream that created this BufferInfo.
                    Stream::Ptr stream;
                    /// \brief
                    /// Write event associated with this buffer.
                    util::ui32 event;

                    /// \brief
                    /// ctor.
                    /// \param[in] stream_ Stream that created this BufferInfo.
                    /// \param[in] event_ Write event associated with this buffer.
                    BufferInfo (
                        Stream &stream_,
                        util::ui32 event_);
                    /// \brief
                    /// Virtual dtor.
                    virtual ~BufferInfo ();

                    /// \brief
                    /// Used by \see{AsyncInfo::WriteBuffers} to write the
                    /// buffer to the given stream.
                    /// \return Count of bytes written.
                    virtual ssize_t Write () = 0;
                    /// \brief
                    /// Used by \see{AsyncInfo::WriteBuffers} to complete
                    /// the write operation and notify \see{AsyncIoEventSink}.
                    /// \return true = \see{AsyncIoEventSink} was notified,
                    /// false = \see{AsyncIoEventSink} was not notified.
                    virtual bool Notify () = 0;
                };
                /// \struct Stream::AsyncInfo::WriteBufferInfo Stream.h thekogans/stream/Stream.h
                ///
                /// \brief
                /// Uses send to write the buffer to the stream.
                struct WriteBufferInfo : public BufferInfo {
                    /// \brief
                    /// WriteBufferInfo has a private heap to help with memory
                    /// management, performance, and global heap fragmentation.
                    THEKOGANS_UTIL_DECLARE_HEAP_WITH_LOCK (WriteBufferInfo, util::SpinLock)

                    /// \brief
                    /// Buffer to write.
                    util::Buffer buffer;

                    /// \brief
                    /// ctor.
                    /// \param[in] stream Stream to write the buffer to.
                    /// \param[in] buffer_ Buffer to write.
                    /// \param[in] count Length of buffer.
                    /// \param[in] useGetBuffer If true, call \see{AsyncIoEventSink::GetBuffer}
                    WriteBufferInfo (
                        Stream &stream,
                        const void *buffer_,
                        std::size_t count,
                        bool useGetBuffer = true);
                    /// \brief
                    /// ctor.
                    /// \param[in] stream_ Stream to write the buffer to.
                    /// \param[in] buffer_ Buffer to write.
                    WriteBufferInfo (
                        Stream &stream,
                        util::Buffer buffer_) :
                        BufferInfo (stream, AsyncInfo::EventWrite),
                        buffer (std::move (buffer_)) {}

                    /// \brief
                    /// Used by \see{AsyncInfo::WriteBuffers} to write
                    /// the buffer to the given stream.
                    /// \return Count of bytes written.
                    virtual ssize_t Write ();
                    /// \brief
                    /// Used by \see{AsyncInfo::WriteBuffers} to complete
                    /// the write operation and notify \see{AsyncIoEventSink}.
                    /// \return true = \see{AsyncIoEventSink} was notified,
                    /// false = \see{AsyncIoEventSink} was not notified.
                    virtual bool Notify ();

                    /// \brief
                    /// WriteBufferInfo is neither copy constructable, nor assignable.
                    THEKOGANS_STREAM_DISALLOW_COPY_AND_ASSIGN (WriteBufferInfo)
                };
                /// \brief
                /// Queue (FIFO) of buffers waiting to be written.
                BufferInfoList bufferInfoList;
                /// \brief
                /// Read deadline maintained by \see{AsyncIoEventQueue}.
                util::TimeSpec readDeadline;
                /// \brief
                /// Write deadline maintained by \see{AsyncIoEventQueue}.
                util::TimeSpec writeDeadline;
            #endif // defined (TOOLCHAIN_OS_Windows)
                /// \brief
                /// Last io event time.
                util::TimeSpec lastEventTime;
                /// \brief
                /// Lock serializing access to overlappedList (Windows) or
                /// bufferInfoList (Linux/OS X).
                util::SpinLock spinLock;

                /// \brief
                /// ctor.
                /// \param[in] eventQueue_ The \see{AsyncIoEventQueue} this
                /// stream is associated with.
                /// \param[in] stream_ Stream this AsyncInfo belongs to.
                /// \param[in] eventSink_ The \see{AsyncIoEventSink} that
                /// will receive notifications.
                /// \param[in] bufferLength_ Buffer length for async
                /// WSARecv(From) and ReadFile.
                /// NOTE: For sockets if bufferLength == 0, a zero
                /// byte read will be initiated \see{AsyncIoEventQueue::AddStream}.
                AsyncInfo (
                    AsyncIoEventQueue &eventQueue_,
                    Stream &stream_,
                    AsyncIoEventSink &eventSink_,
                    std::size_t bufferLength_);
                /// \brief
                /// dtor.
                ~AsyncInfo ();

                /// \brief
                /// Relase all resources (\see{BufferInfo}, \see{AsyncIoEventQueue},
                /// \see{Stream}, \see{AsyncIoEventSink}) associated with this \see{AsyncInfo}.
                /// NOTE: This method is called by the \see{AsyncIoEventQueue}::DeleteStream.
                void ReleaseResources ();

            #if defined (TOOLCHAIN_OS_Windows)
                /// \brief
                /// Add an Overlapped to the overlappedList.
                /// \param[in] overlapped Overlapped to add.
                void AddOverlapped (Overlapped *overlapped);
                /// \brief
                /// Delete an Overlapped from the overlappedList.
                /// \param[in] overlapped Overlapped to delete.
                void DeleteOverlapped (Overlapped *overlapped);
            #else // defined (TOOLCHAIN_OS_Windows)
                /// \brief
                /// Add an BufferInfo to the bufferInfoList.
                /// \param[in] bufferInfo BufferInfo to add.
                void AddBufferInfo (BufferInfo *bufferInfo);
                /// \brief
                /// Delete an BufferInfo from the overlappedList.
                /// \param[in] bufferInfo BufferInfo to delete.
                void DeleteBufferInfo (BufferInfo *bufferInfo);

                /// \brief
                /// Adds \see{AsyncIoEventQueue} events the stream is
                /// interested in.
                /// \param[in] events Events the stream is interested in.
                void AddStreamForEvents (util::ui32 events);
                /// \brief
                /// Deletes \see{AsyncIoEventQueue} events the stream is
                /// no longer interested in.
                /// \param[in] events Events the stream is no
                /// longer interested in.
                void DeleteStreamForEvents (util::ui32 events);
                /// \brief
                /// When a user calls Stream::Write, if the stream
                /// is async, queue the buffer for writing.
                /// \param[in] buffer Buffer to queue.
                void EnqBuffer (BufferInfo::Ptr buffer);
                /// \brief
                /// Called by \see{Stream::HandleAsyncEvent} when processing
                /// the EventWrite, EventWriteTo and EventWriteMsg events.
                /// Writes the pending buffers to the stream.
                void WriteBuffers ();

                /// \brief
                /// Return true if the read operation timed out.
                /// \param[in] currentTime Current time.
                /// \return true if the read operation timed out.
                inline bool ReadTimedOut (const util::TimeSpec &currentTime) const {
                    return readDeadline != util::TimeSpec::Zero && currentTime >= readDeadline;
                }
                /// \brief
                /// Return true if the write operation timed out.
                /// \param[in] currentTime Current time.
                /// \return true if the write operation timed out.
                inline bool WriteTimedOut (const util::TimeSpec &currentTime) const {
                    return writeDeadline != util::TimeSpec::Zero && currentTime >= writeDeadline;
                }
            #endif // defined (TOOLCHAIN_OS_Windows)

                /// \brief
                /// Update the deadlines of a timed stream.
                /// \param[in] events Events for which to check.
                /// \param[in] doBreak Call \see{AsyncIoEventQueue::Break}
                /// after updating.
                /// \return true = stream is timed, false = stream is not timed.
                bool UpdateTimedStream (
                    util::ui32 events,
                    bool doBreak = true);

                /// \brief
                /// AsyncInfo is neither copy constructable, nor assignable.
                THEKOGANS_STREAM_DISALLOW_COPY_AND_ASSIGN (AsyncInfo)
            };
            /// \brief
            /// Async state.
            AsyncInfo::Ptr asyncInfo;

            /// \brief
            /// Used by the \see{AsyncIoEventQueue::AddStream} to allow
            /// the stream to initialize itself. When this function is called,
            /// the stream is already async, and Stream::AsyncInfo has been
            /// created. At this point the stream should do whatever
            /// stream specific initialization it needs to.
            virtual void InitAsyncIo () = 0;
            /// \brief
            /// Used by the \see{AsyncIoEventQueue::DeleteStream} to allow
            /// the stream to cleanup after itself. When this function is
            /// called, the stream is no longer async. At this point the
            /// stream should do whatever stream specific deinitialization
            /// it needs to.
            virtual void TerminateAsyncIo () {}
            /// \brief
            /// Used by the \see{AsyncIoEventQueue} to notify the stream
            /// of async errors.
            /// \param[in] exception Async error.
            virtual void HandleError (const util::Exception &exception) throw ();
        #if defined (TOOLCHAIN_OS_Windows)
            /// \struct Stream::TimedOverlapped Stream.h thekogans/stream/Stream.h
            ///
            /// \brief
            /// TimedOverlapped provides the mechanism by which named pipes
            /// do timed synchronous io.
            struct TimedOverlapped :
                    public OVERLAPPED,
                    public util::ThreadSafeRefCounted {
                /// \brief
                /// Convenient typedef for util::ThreadSafeRefCounted::Ptr<TimedOverlapped>.
                typedef util::ThreadSafeRefCounted::Ptr<TimedOverlapped> Ptr;

                /// \brief
                /// TimedOverlapped has a private heap to help with memory
                /// management, performance, and global heap fragmentation.
                THEKOGANS_UTIL_DECLARE_HEAP_WITH_LOCK (TimedOverlapped, util::SpinLock)

                /// \brief
                /// ctor.
                TimedOverlapped ();
                /// \brief
                /// dtor.
                ~TimedOverlapped ();

                /// \brief
                /// Wait for io to complete.
                /// \param[in] handle NamedPipe handle to wait on.
                /// \param[in] timeSpec How long to wait.
                /// \return Count of bytes transffered.
                DWORD Wait (
                    THEKOGANS_UTIL_HANDLE handle,
                    const util::TimeSpec &timeSpec);

                /// \brief
                /// TimedOverlapped is neither copy constructable, nor assignable.
                THEKOGANS_STREAM_DISALLOW_COPY_AND_ASSIGN (TimedOverlapped)
            };

            /// \brief
            /// Used by \see{AsyncIoEventQueue} to notify the stream that
            /// an overlapped operation has completed successfully.
            /// \param[in] overlapped \see{Overlapped} that completed successfully.
            virtual void HandleOverlapped (AsyncInfo::Overlapped & /*overlapped*/) throw () = 0;
            /// \brief
            /// Used by \see{AsyncIoEventQueue} to notify the stream that
            /// an overlapped operation has timed out.
            /// \param[in] overlapped \see{Overlapped} that timed out.
            virtual void HandleTimedOutOverlapped (AsyncInfo::Overlapped & /*overlapped*/) throw ();
        #else // defined (TOOLCHAIN_OS_Windows)
            /// \struct Stream::TimedEvent Stream.h thekogans/stream/Stream.h
            ///
            /// \brief
            /// TimedEvent provides the mechanism by which pipes
            /// do timed synchronous io.
            struct TimedEvent {
            private:
                /// \brief
                /// epoll/kqueue handle.
                THEKOGANS_UTIL_HANDLE handle;

            public:
                /// \brief
                /// ctor.
                TimedEvent ();
                /// \brief
                /// dtor.
                ~TimedEvent ();

                /// \brief
                /// Wait for event or timeout.
                /// \param[in] stream Stream to wait on.
                /// \param[in] event Event to monitor for (Event[Read | Write])
                /// \param[in] timeSpec Time interval to wait.
                /// \return true = got event, false = timed out.
                bool Wait (
                    THEKOGANS_UTIL_HANDLE stream,
                    util::ui32 event,
                    const util::TimeSpec &timeSpec);

                /// \brief
                /// TimedEvent is neither copy constructable, nor assignable.
                THEKOGANS_STREAM_DISALLOW_COPY_AND_ASSIGN (TimedEvent)
            };

            /// \brief
            /// Used by \see{AsyncIoEventQueue} to notify the stream of
            /// pending io event.
            /// \param[in] event Async io event enum.
            virtual void HandleAsyncEvent (util::ui32 /*event*/) throw () = 0;
            /// \brief
            /// Used by \see{AsyncIoEventQueue} to notify the stream of
            /// pending io event that timed out.
            /// \param[in] event Async io event enum.
            virtual void HandleTimedOutAsyncEvent (util::ui32 /*event*/) throw ();
        #endif // defined (TOOLCHAIN_OS_Windows)

            /// \brief
            /// \see{StreamSelector} needs access to the handle.
            friend struct StreamSelector;
            /// \brief
            /// \see{AsyncIoEventQueue} needs access to the AsyncInfo.
            friend struct AsyncIoEventQueue;

            /// \brief
            /// Stream is neither copy constructable, nor assignable.
            THEKOGANS_STREAM_DISALLOW_COPY_AND_ASSIGN (Stream)
        };

    #if defined (_MSC_VER)
        #pragma warning (pop)
    #endif // defined (_MSC_VER)

        /// \def THEKOGANS_STREAM_DECLARE_STREAM_COMMON(type, base)
        /// This macro is used in a stream declaration file (.h).
        /// It sets up everything needed for the stream to be dynamically
        /// discoverable, and creatable.
        /// \param[in] type Stream class name.
        #define THEKOGANS_STREAM_DECLARE_STREAM_COMMON(type)\
            typedef thekogans::util::ThreadSafeRefCounted::Ptr<type> Ptr;\
            THEKOGANS_UTIL_DECLARE_HEAP_WITH_LOCK (type, thekogans::util::SpinLock)\
        public:\
            static thekogans::stream::Stream::Context::Ptr CreateContext (\
                    const pugi::xml_node &node) {\
                return thekogans::stream::Stream::Context::Ptr (\
                    new type::Context (node));\
            }

        /// \def THEKOGANS_STREAM_IMPLEMENT_STREAM_COMMON(type)
        /// This macro is used in the stream definition file (.cpp).
        /// It sets up everything needed for the stream to be dynamically
        /// discoverable, and creatable.
        /// \param[in] type Stream class name.
        #define THEKOGANS_STREAM_IMPLEMENT_STREAM_COMMON(type)\
            THEKOGANS_UTIL_IMPLEMENT_HEAP_WITH_LOCK (type, thekogans::util::SpinLock)
    #if defined (THEKOGANS_STREAM_TYPE_Static)
        /// \def THEKOGANS_STREAM_DECLARE_STREAM(type, base)
        /// This macro is used in a stream declaration file (.h).
        /// It sets up everything needed for the stream to be dynamically
        /// discoverable, and creatable.
        /// \param[in] type Stream class name.
        #define THEKOGANS_STREAM_DECLARE_STREAM(type)\
            THEKOGANS_STREAM_DECLARE_STREAM_COMMON(type)\
            static void StaticInit () {\
                static volatile bool registered = false;\
                static thekogans::util::SpinLock spinLock;\
                if (!registered) {\
                    thekogans::util::LockGuard<thekogans::util::SpinLock> guard (spinLock);\
                    if (!registered) {\
                        std::pair<Map::iterator, bool> result =\
                            GetMap ().insert (Map::value_type (#type, type::CreateContext));\
                        if (!result.second) {\
                            THEKOGANS_UTIL_THROW_STRING_EXCEPTION (\
                                "'%s' is already registered.", #type);\
                        }\
                        registered = true;\
                    }\
                }\
            }

        /// \def THEKOGANS_STREAM_IMPLEMENT_STREAM(type)
        /// This macro is used in the stream definition file (.cpp).
        /// It sets up everything needed for the stream to be dynamically
        /// discoverable, and creatable.
        /// \param[in] type Stream class name.
        #define THEKOGANS_STREAM_IMPLEMENT_STREAM(type)\
            THEKOGANS_STREAM_IMPLEMENT_STREAM_COMMON(type)
    #else // defined (THEKOGANS_STREAM_TYPE_Static)
        /// \def THEKOGANS_STREAM_DECLARE_STREAM(type, base)
        /// This macro is used in a stream declaration file (.h).
        /// It sets up everything needed for the stream to be dynamically
        /// discoverable, and creatable.
        /// \param[in] type Stream class name.
        #define THEKOGANS_STREAM_DECLARE_STREAM(type)\
            THEKOGANS_STREAM_DECLARE_STREAM_COMMON(type)\
            static const thekogans::stream::Stream::MapInitializer mapInitializer;

        /// \def THEKOGANS_STREAM_IMPLEMENT_STREAM(type)
        /// This macro is used in the stream definition file (.cpp).
        /// It sets up everything needed for the stream to be dynamically
        /// discoverable, and creatable.
        /// \param[in] type Stream class name.
        #define THEKOGANS_STREAM_IMPLEMENT_STREAM(type)\
            THEKOGANS_STREAM_IMPLEMENT_STREAM_COMMON(type)\
            const thekogans::stream::Stream::MapInitializer type::mapInitializer (\
                #type, type::CreateContext);
    #endif // defined (THEKOGANS_STREAM_TYPE_Static)

    } // namespace stream
} // namespace thekogans

#endif // !defined (__thekogans_stream_Stream_h)
