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
#include "thekogans/util/Environment.h"
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

        struct _LIB_THEKOGANS_STREAM_DECL StreamEvents : public virtual util::RefCounted {
            /// \brief
            /// Declare \see{util::RefCounted} pointers.
            THEKOGANS_UTIL_DECLARE_REF_COUNTED_POINTERS (StreamEvents)

            /// \brief
            /// dtor.
            virtual ~StreamEvents () {}

            /// \brief
            /// Called to initiate stream error processing.
            /// \param[in] stream \see{Stream} on which an error occurred.
            /// \param[in] exception \see{util::Exception} representing the error.
            virtual void OnStreamError (
                util::RefCounted::SharedPtr<Stream> /*stream*/,
                const util::Exception & /*exception*/) throw () {}

            /// \brief
            /// Called when a remote peer has disconnected.
            /// \param[in] stream \see{Stream} which has been disconnected.
            virtual void OnStreamOpen (
                util::RefCounted::SharedPtr<Stream> /*stream*/) throw () {}
            /// \brief
            /// Called when a remote peer has disconnected.
            /// \param[in] stream \see{Stream} which has been disconnected.
            virtual void OnStreamClose (
                util::RefCounted::SharedPtr<Stream> /*stream*/) throw () {}

            /// \brief
            /// Called when new data has arrived on a stream.
            /// \param[in] stream \see{Stream} that received the data.
            /// \param[in] buffer The new data.
            virtual void OnStreamRead (
                util::RefCounted::SharedPtr<Stream> /*stream*/,
                util::Buffer /*buffer*/) throw () {}
            /// \brief
            /// Called when data was written to a stream.
            /// \param[in] stream Stream where data was written.
            /// \param[in] buffer The written data.
            virtual void OnStreamWrite (
                util::RefCounted::SharedPtr<Stream> /*stream*/,
                util::Buffer /*buffer*/) throw () {}
        };


    #if !defined (TOOLCHAIN_OS_Windows)
        /// \brief
        /// Convenient typedef for util::RefCounted::Registry<Stream>.
        typedef util::RefCounted::Registry<Stream> StreamRegistry;
    #endif // !defined (TOOLCHAIN_OS_Windows)

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

        struct _LIB_THEKOGANS_STREAM_DECL Stream : public thekogans::util::Producer<StreamEvents> {
            /// \brief
            /// Declare \see{RefCounted} pointers.
            THEKOGANS_UTIL_DECLARE_REF_COUNTED_POINTERS (Stream)

        protected:
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
            /// \param[in] event Stream event.
            /// \return String equivalent of event.
            static std::string eventToString (util::ui32 event);
            /// \brief
            /// Convert string form of event in to Stream event.
            /// \param[in] event String equivalent of event.
            /// \return Stream event.
            static util::ui32 stringToEvent (const std::string &event);

            /// \brief
            /// Stream handle.
            THEKOGANS_UTIL_HANDLE handle;
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
        #if defined (TOOLCHAIN_OS_Windows)
            /// \struct Stream::Overlapped Stream.h thekogans/stream/Stream.h
            ///
            /// \brief
            /// Overlapped extends a Windows WSAOVERLAPPED.
            struct Overlapped :
                    public WSAOVERLAPPED,
                    public OverlappedList::Node,
                    public util::RefCounted {
                /// \brief
                /// Declare \see{RefCounted} pointers.
                THEKOGANS_UTIL_DECLARE_REF_COUNTED_POINTERS (Overlapped)

                /// \brief
                /// Stream that created this Overlapped.
                Stream::SharedPtr stream;
                /// \brief
                /// Operation represented by this Overlapped.
                util::ui32 event;

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
            /// \struct Stream::ReadWrietOverlapped Stream.h thekogans/stream/Stream.h
            ///
            /// \brief
            /// ReadWriteOverlapped is a helper class. It reduces code clutter and
            /// makes instantiating Overlapped used by \see{Stream::Read} and
            /// \see{Stream::Write} easier.
            struct ReadWriteOverlapped : public Overlapped {
                /// \brief
                /// Declare \see{RefCounted} pointers.
                THEKOGANS_UTIL_DECLARE_REF_COUNTED_POINTERS (ReadWriteOverlapped)

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
                        Overlapped (stream, Stream::EventWrite),
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
        #else // defined (TOOLCHAIN_OS_Windows)
            /// \brief
            /// \see{StreamRegistry} token.
            StreamRegistry::Token token;
            /// \brief
            /// Events mask that records the events this
            /// stream is interested in.
            util::ui32 events;
            /// \struct Stream::Overlapped Stream.h thekogans/stream/Stream.h
            ///
            /// \brief
            /// Overlapped is a virtual base for buffers used for async
            /// Stream::Write. Various derivatives represent concrete
            /// Overlapped for Write, WriteTo and WriteMsg.
            struct Overlapped :
                    public OverlappedList::Node,
                    public util::RefCounted {
                /// \brief
                /// Declare \see{RefCounted} pointers.
                THEKOGANS_UTIL_DECLARE_REF_COUNTED_POINTERS (Overlapped)

                /// \brief
                /// Stream that created this Overlapped.
                Stream::SharedPtr stream;
                /// \brief
                /// Write event associated with this buffer.
                util::ui32 event;

                /// \brief
                /// ctor.
                /// \param[in] stream_ Stream that created this Overlapped.
                /// \param[in] event_ Write event associated with this buffer.
                Overlapped (
                    Stream &stream_,
                    util::ui32 event_) :
                    stream (&stream_),
                    event (event_) {}
                /// \brief
                /// Virtual dtor.
                virtual ~Overlapped () {}

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
            /// \struct Stream::AsyncInfo::WriteOverlapped Stream.h thekogans/stream/Stream.h
            ///
            /// \brief
            /// Uses send to write the buffer to the stream.
            struct WriteOverlapped : public Overlapped {
                /// \brief
                /// Declare \see{RefCounted} pointers.
                THEKOGANS_UTIL_DECLARE_REF_COUNTED_POINTERS (WriteOverlapped)

                /// \brief
                /// WriteOverlapped has a private heap to help with memory
                /// management, performance, and global heap fragmentation.
                THEKOGANS_UTIL_DECLARE_HEAP_WITH_LOCK (WriteOverlapped, util::SpinLock)

                /// \brief
                /// Buffer to write.
                util::Buffer buffer;

                /// \brief
                /// ctor.
                /// \param[in] stream Stream to write the buffer to.
                /// \param[in] buffer_ Buffer to write.
                /// \param[in] count Length of buffer.
                /// \param[in] useGetBuffer If true, call \see{AsyncIoEventSink::GetBuffer}
                WriteOverlapped (
                    Stream &stream,
                    const void *buffer_,
                    std::size_t count,
                    bool useGetBuffer = true);
                /// \brief
                /// ctor.
                /// \param[in] stream_ Stream to write the buffer to.
                /// \param[in] buffer_ Buffer to write.
                WriteOverlapped (
                    Stream &stream,
                    util::Buffer buffer_) :
                    Overlapped (stream, AsyncInfo::EventWrite),
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
                /// WriteOverlapped is neither copy constructable, nor assignable.
                THEKOGANS_STREAM_DISALLOW_COPY_AND_ASSIGN (WriteOverlapped)
            };
        #endif // defined (TOOLCHAIN_OS_Windows)
            /// \brief
            /// Outstanding overlapped io.
            OverlappedList overlappedList;
            /// \brief
            /// Lock serializing access to overlappedList (Windows) or
            /// bufferInfoList (Linux/OS X).
            util::SpinLock spinLock;

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
            /// Used by an async Stream::Write to put a
            /// partially written buffer back on the queue.
            /// \param[in] buffer Buffer to queue.
            void EnqBufferFront (Overlapped::SharedPtr buffer);
            /// \brief
            /// When a user calls Stream::Write, if the stream
            /// is async, to queue the buffer for writing.
            /// \param[in] buffer Buffer to queue.
            void EnqBufferBack (Overlapped::SharedPtr buffer);
            /// \brief
            /// Called by Stream::Write to remove the head
            /// buffer from the queue and put it on the wire
            /// \return Head buffer.
            Overlapped::SharedPtr DeqBuffer ();
            /// \brief
            /// Called by \see{Stream::HandleAsyncEvent} when processing
            /// the EventWrite, EventWriteTo and EventWriteMsg events.
            /// Writes the pending buffers to the stream.
            void WriteBuffers ();
        #endif // defined (TOOLCHAIN_OS_Windows)

            /// \brief
            /// Used by Read handlers to hook the buffer creation process.
            /// This technique is very useful for protocol filters. If
            /// you're writing a filter that has it's own protocol header
            /// that it needs to wrap the buffer with (before sending it
            /// along for upstream processing) override this api and allocate
            /// a buffer big enough to hold your header + bufferSize.
            /// \param[in] stream \see{Stream} that received the packet.
            /// \param[in] count Minimum buffer size (packet size).
            /// \return Buffer of appropriate size.
            virtual util::Buffer GetBuffer (
                    Stream & /*stream*/,
                    util::Endianness endianness,
                    std::size_t count) {
                return util::Buffer (endianness, count);
            }

            /// \brief
            /// The analog to the GetBuffer above. Used by Write handler
            /// to allow the sink to add appropriate protocol headers.
            /// \param[in] stream \see{Stream} that will receive the buffer.
            /// \param[in] buffer \see{Stream::Write} bufffer.
            /// \param[in] count \see{Stream::Write} buffer length.
            /// \return \see{util::Buffer} to write to the stream.
            virtual util::Buffer GetBuffer (
                    Stream & /*stream*/,
                    util::Endianness endianness,
                    const void *buffer,
                    std::size_t count) {
                return util::Buffer (
                    endianness,
                    (const util::ui8 *)buffer,
                    (const util::ui8 *)buffer + count);
            }

        public:
            enum {
                /// \brief
                /// Default buffer length for async WSARecv[From | Msg].
                DEFAULT_BUFFER_LENGTH = 16384
            };

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
            static Context::SharedPtr GetContext (const pugi::xml_node &node);
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
            /// Close the stream.
            virtual void Close ();

        protected:
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
            virtual void TerminateAsyncIo () {
                Close ();
            }
            /// \brief
            /// Used by the \see{AsyncIoEventQueue} to notify the stream
            /// of async errors.
            /// \param[in] exception Async error.
            virtual void HandleError (const util::Exception &exception) throw ();
        #if defined (TOOLCHAIN_OS_Windows)
            /// \brief
            /// Used by \see{AsyncIoEventQueue} to notify the stream that
            /// an overlapped operation has completed successfully.
            /// \param[in] overlapped \see{Overlapped} that completed successfully.
            virtual void HandleOverlapped (AsyncInfo::Overlapped & /*overlapped*/) throw () = 0;
        #else // defined (TOOLCHAIN_OS_Windows)
            /// \brief
            /// Used by \see{AsyncIoEventQueue} to notify the stream of
            /// pending io event.
            /// \param[in] event Async io event enum.
            virtual void HandleAsyncEvent (util::ui32 /*event*/) throw () = 0;
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

        /// \def THEKOGANS_STREAM_DECLARE_STREAM_COMMON(type, base)
        /// This macro is used in a stream declaration file (.h).
        /// It sets up everything needed for the stream to be dynamically
        /// discoverable, and creatable.
        /// \param[in] type Stream class name.
        #define THEKOGANS_STREAM_DECLARE_STREAM_COMMON(type)\
            THEKOGANS_UTIL_DECLARE_REF_COUNTED_POINTERS (type)\
            THEKOGANS_UTIL_DECLARE_HEAP_WITH_LOCK (type, thekogans::util::SpinLock)\
        public:\
            static thekogans::stream::Stream::Context::SharedPtr CreateContext (\
                    const pugi::xml_node &node) {\
                return thekogans::stream::Stream::Context::SharedPtr (\
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
            THEKOGANS_STREAM_DECLARE_STREAM_COMMON (type)\
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
            THEKOGANS_STREAM_IMPLEMENT_STREAM_COMMON (type)
    #else // defined (THEKOGANS_STREAM_TYPE_Static)
        /// \def THEKOGANS_STREAM_DECLARE_STREAM(type, base)
        /// This macro is used in a stream declaration file (.h).
        /// It sets up everything needed for the stream to be dynamically
        /// discoverable, and creatable.
        /// \param[in] type Stream class name.
        #define THEKOGANS_STREAM_DECLARE_STREAM(type)\
            THEKOGANS_STREAM_DECLARE_STREAM_COMMON (type)\
            static const thekogans::stream::Stream::MapInitializer mapInitializer;

        /// \def THEKOGANS_STREAM_IMPLEMENT_STREAM(type)
        /// This macro is used in the stream definition file (.cpp).
        /// It sets up everything needed for the stream to be dynamically
        /// discoverable, and creatable.
        /// \param[in] type Stream class name.
        #define THEKOGANS_STREAM_IMPLEMENT_STREAM(type)\
            THEKOGANS_STREAM_IMPLEMENT_STREAM_COMMON (type)\
            const thekogans::stream::Stream::MapInitializer type::mapInitializer (\
                #type, type::CreateContext);
    #endif // defined (THEKOGANS_STREAM_TYPE_Static)

    } // namespace stream
} // namespace thekogans

#endif // !defined (__thekogans_stream_Stream_h)
