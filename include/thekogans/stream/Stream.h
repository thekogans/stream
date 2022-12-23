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
#include "thekogans/util/Subscriber.h"
#include "thekogans/util/Producer.h"
#include "thekogans/stream/Config.h"
#include "thekogans/stream/Address.h"
#include "thekogans/stream/MsgHdr.h"

namespace thekogans {
    namespace stream {

        /// \brief
        /// Forward declaration of \see{AsyncIoEventQueue}.
        struct AsyncIoEventQueue;
        /// \brief
        /// Forward declaration of Stream.
        struct Stream;

        /// \brief
        /// Convenient typedef for util::RefCounted::Registry<Stream>.
        /// NOTE: It's one and only instance is accessed like this;
        /// thekogans::stream::StreamRegistry::Instance ().
        typedef util::RefCounted::Registry<Stream> StreamRegistry;

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
            /// Called to initiate stream normal disconnect processing.
            /// \param[in] stream \see{Stream} that disconnected.
            virtual void OnStreamDisconnect (
                util::RefCounted::SharedPtr<Stream> /*stream*/) throw () {}

            /// \brief
            /// Called when new data has arrived on a stream.
            /// \param[in] stream \see{Stream} that received the data.
            /// \param[in] buffer The new data.
            virtual void OnStreamRead (
                util::RefCounted::SharedPtr<Stream> /*stream*/,
                const util::Buffer & /*buffer*/) throw () {}
            /// \brief
            /// Called when data was written to a stream.
            /// \param[in] stream Stream where data was written.
            /// \param[in] buffer The written data.
            virtual void OnStreamWrite (
                util::RefCounted::SharedPtr<Stream> /*stream*/,
                const util::Buffer & /*buffer*/) throw () {}
        };

        /// \struct Stream Stream.h thekogans/stream/Stream.h
        ///
        /// \brief
        /// Stream is an abstract base for all other stream types.
        /// It's main purpose is to expose the api a generic stream
        /// will have. Streams are reference counted. This makes it
        /// very easy to deal with lifetimes of async streams (especially
        /// on Windows). Because of the design of \see{util::RefCounted},
        /// creating a stream on the stack is as simple as declaring it.
        /// No allocation/deallocation necessary.
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

        protected:
            /// \brief
            /// Stream os handle.
            THEKOGANS_UTIL_HANDLE handle;
            /// \brief
            /// This token is the key between the c++ and the c async io worlds (os).
            /// This token is registered with os specific apis (io completion port on
            /// windows, epoll on linux and kqueue on os x). On callback the token
            /// is used to get a Stream::SharedPtr from the Stream::WeakPtr found in
            /// the \see{util::RefCounted::Registry}.
            StreamRegistry::Token token;
        #if !defined (TOOLCHAIN_OS_Windows)
            struct WSAOVERLAPPED {
                THEKOGANS_UTIL_ERROR_CODE errorCode;
                WSAOVERLAPPED () :
                    errorCode (0) {}
                virtual ~WSAOVERLAPPED () {}
            };
        #endif // !defined (TOOLCHAIN_OS_Windows)
            /// \struct Stream::Overlapped Stream.h thekogans/stream/Stream.h
            ///
            /// \brief
            /// Overlapped extends a Windows WSAOVERLAPPED.
            struct Overlapped : public WSAOVERLAPPED {
                /// \brief
                /// ctor.
                Overlapped () {
                #if defined (TOOLCHAIN_OS_Windows)
                    memset ((WSAOVERLAPPED *)this, 0, sizeof (WSAOVERLAPPED));
                #endif defined (TOOLCHAIN_OS_Windows)
                }
                /// \brief
                /// dtor.
                virtual ~Overlapped () {}

                /// \brief
                virtual ssize_t Prolog (Stream::SharedPtr /*stream*/) throw () = 0;
                /// \brief
                virtual bool Epilog (Stream::SharedPtr /*stream*/) throw () {
                    return true;
                }

                /// \brief
                /// Return overlapped name.
                /// \return overlapped name.
                inline const char *GetName () const {
                    return typeid (*this).name ();
                }

                /// \brief
                /// Return error code.
                /// \return Error code.
                inline THEKOGANS_UTIL_ERROR_CODE GetError () const {
                #if defined (TOOLCHAIN_OS_Windows)
                    return (THEKOGANS_UTIL_ERROR_CODE)Internal;
                #else // defined (TOOLCHAIN_OS_Windows)
                    return errorCode;
                #endif defined (TOOLCHAIN_OS_Windows)
                }
                /// \brief
                /// Set error code.
                /// \param[in] error Error code.
                inline void SetError (THEKOGANS_UTIL_ERROR_CODE errorCode_) {
                #if defined (TOOLCHAIN_OS_Windows)
                    Internal = (DWORD)errorCode_;
                #else // defined (TOOLCHAIN_OS_Windows)
                    errorCode = errorCode_;
                #endif defined (TOOLCHAIN_OS_Windows)
                }

            #if defined (TOOLCHAIN_OS_Windows)
                /// \brief
                /// Return count of bytes read or written.
                /// \return Count of bytes read or written.
                inline util::ui32 GetCount () const {
                    return InternalHigh;
                }
                /// \brief
                /// Set count of bytes read or written.
                /// \param[in] count Count of bytes read or written.
                inline void SetCount (util::ui32 count) {
                    InternalHigh = count_;
                }
            #endif defined (TOOLCHAIN_OS_Windows)

                /// \brief
                /// Overlapped is neither copy constructable, nor assignable.
                THEKOGANS_STREAM_DISALLOW_COPY_AND_ASSIGN (Overlapped)
            };
            /// \struct Stream::ReadOverlapped Stream.h thekogans/stream/Stream.h
            ///
            /// \brief
            /// ReadOverlapped is a helper class. It reduces code clutter and
            /// makes instantiating Overlapped used by \see{Stream::Read} easier.
            struct ReadOverlapped : public Overlapped {
                /// \brief
                /// ReadOverlapped has a private heap to help with memory
                /// management, performance, and global heap fragmentation.
                THEKOGANS_UTIL_DECLARE_HEAP_WITH_LOCK (ReadOverlapped, util::SpinLock)

                /// \brief
                /// Buffer used by Stream::Read.
                util::Buffer buffer;
            #if defined (TOOLCHAIN_OS_Windows)
                /// \brief
                /// WSARecv buffer.
                WSABUF wsaBuf;
                /// \brief
                /// WSARecv flags.
                DWORD flags;
            #endif defined (TOOLCHAIN_OS_Windows)

                /// \brief
                /// Read ctor.
                /// \param[in] bufferLength Length of buffer to allocate for reading.
                ReadOverlapped (std::size_t bufferLength) :
                    buffer (util::NetworkEndian, bufferLength)
                #if defined (TOOLCHAIN_OS_Windows)
                    , flags (0)
                #endif defined (TOOLCHAIN_OS_Windows)
                {
                #if defined (TOOLCHAIN_OS_Windows)
                    wsaBuf.len = (ULONG)buffer.GetDataAvailableForWriting ();
                    wsaBuf.buf = (char *)buffer.GetWritePtr ();
                #endif defined (TOOLCHAIN_OS_Windows)
                }

                /// \brief
                /// Used by \see{PumpAsyncIo} to
                /// the buffer to the given stream.
                /// \param[in] stream Stream that created this Overlapped.
                /// \return Count of bytes written.
                virtual ssize_t Prolog (Stream::SharedPtr stream) throw () override;
                /// \brief
                /// Called by \see{AsyncIoEventQueue::WaitForEvents} to allow
                /// the ReadOverlapped to perform post op housekeeping.
                virtual bool Epilog (Stream::SharedPtr /*stream*/) throw () override {
                    return !buffer.IsEmpty ();
                }

                /// \brief
                /// ReadOverlapped is neither copy constructable, nor assignable.
                THEKOGANS_STREAM_DISALLOW_COPY_AND_ASSIGN (ReadOverlapped)
            };
            /// \struct Stream::WrietOverlapped Stream.h thekogans/stream/Stream.h
            ///
            /// \brief
            /// WriteOverlapped is a helper class. It reduces code clutter and
            /// makes instantiating Overlapped used by \see{Stream::Write} easier.
            struct WriteOverlapped : public Overlapped {
                /// \brief
                /// WriteOverlapped has a private heap to help with memory
                /// management, performance, and global heap fragmentation.
                THEKOGANS_UTIL_DECLARE_HEAP_WITH_LOCK (WriteOverlapped, util::SpinLock)

                /// \brief
                /// Buffer used by Stream::/Write.
                util::Buffer buffer;
            #if defined (TOOLCHAIN_OS_Windows)
                /// \brief
                /// WSASend buffer.
                WSABUF wsaBuf;
                /// \brief
                /// WSASend flags.
                DWORD flags;
            #endif defined (TOOLCHAIN_OS_Windows)

                /// \brief
                /// Write ctor.
                /// \param[in] buffer_ Buffer to write.
                /// \param[in] bufferLength Lenght of buffer.
                WriteOverlapped (
                    const void *buffer_,
                    std::size_t bufferLength) :
                    buffer (
                        util::NetworkEndian,
                        (const util::ui8 *)buffer_,
                        (const util::ui8 *)buffer_ + bufferLength)
                #if defined (TOOLCHAIN_OS_Windows)
                    , flags (0)
                #endif // defined (TOOLCHAIN_OS_Windows)
                {
                #if defined (TOOLCHAIN_OS_Windows)
                    wsaBuf.len = (ULONG)buffer.GetDataAvailableForReading ();
                    wsaBuf.buf = (char *)buffer.GetReadPtr ();
                #endif // defined (TOOLCHAIN_OS_Windows)
                }
                /// \brief
                /// Write ctor.
                /// \param[in] buffer Buffer to write.
                WriteOverlapped (util::Buffer buffer_) :
                    buffer (std::move (buffer_))
                #if defined (TOOLCHAIN_OS_Windows)
                    , flags (0)
                #endif // defined (TOOLCHAIN_OS_Windows)
                {
                #if defined (TOOLCHAIN_OS_Windows)
                    wsaBuf.len = (ULONG)buffer.GetDataAvailableForReading ();
                    wsaBuf.buf = (char *)buffer.GetReadPtr ();
                #endif // defined (TOOLCHAIN_OS_Windows)
                }

                /// \brief
                /// Used by \see{PumpAsyncIo} to write
                /// the buffer to the given stream.
                /// \param[in] stream Stream that created this Overlapped.
                /// \return Count of bytes written.
                virtual ssize_t Prolog (Stream::SharedPtr stream) throw () override;
                /// \brief
                /// Called by \see{AsyncIoEventQueue::WaitForEvents} to allow
                /// the WriteOverlapped to perform post op housekeeping.
                virtual bool Epilog (Stream::SharedPtr /*stream*/) throw () override {
                    return buffer.IsEmpty ();
                }

                /// \brief
                /// WriteOverlapped is neither copy constructable, nor assignable.
                THEKOGANS_STREAM_DISALLOW_COPY_AND_ASSIGN (WriteOverlapped)
            };
        #if !defined (TOOLCHAIN_OS_Windows)
            /// \brief
            /// Outstanding read requests.
            std::list<std::unique_ptr<Overlapped>> in;
            /// \brief
            /// Outstanding write requests.
            std::list<std::unique_ptr<Overlapped>> out;
            /// \brief
            /// Lock serializing access to in and out.
            util::SpinLock spinLock;
        #endif // !defined (TOOLCHAIN_OS_Windows)

        public:
            /// \brief
            /// ctor.
            /// \param[in] handle_ OS stream handle.
            Stream (THEKOGANS_UTIL_HANDLE handle_);
            /// \brief
            /// dtor.
            virtual ~Stream ();

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

            virtual std::size_t GetDataAvailable () const = 0;
            enum {
                /// \brief
                /// Default buffer length for async WSARecv[From | Msg].
                DEFAULT_BUFFER_LENGTH = 16384
            };
            /// \brief
            /// Read bytes from the stream.
            /// \param[in] bufferLength Buffer length for async WSARecv[From | Msg].
            virtual void Read (std::size_t /*bufferLength*/ = DEFAULT_BUFFER_LENGTH) = 0;
            /// \brief
            /// Write bytes to the stream.
            /// \param[in] buffer Bytes to write.
            /// \param[in] count Buffer length.
            virtual void Write (
                const void * /*buffer*/,
                std::size_t /*count*/) = 0;
            /// \brief
            /// Write buffer the stream.
            /// \param[in] buffer Buffer to write.
            virtual void Write (util::Buffer /*buffer*/) = 0;

        protected:
            /// \brief
            /// Used by the \see{AsyncIoEventQueue} to notify the stream
            /// of async errors.
            /// \param[in] exception Async error.
            virtual void HandleError (const util::Exception &exception) throw ();
            /// \brief
            /// Used by the \see{AsyncIoEventQueue} to notify the stream
            /// of async errors.
            /// \param[in] exception Async error.
            virtual void HandleDisconnect () throw ();
            /// \brief
            /// Used by \see{AsyncIoEventQueue} to notify the stream that
            /// an overlapped operation has completed successfully.
            /// \param[in] overlapped \see{Overlapped} that completed successfully.
            virtual void HandleOverlapped (Overlapped & /*overlapped*/) throw () = 0;
        #if !defined (TOOLCHAIN_OS_Windows)
            /// \brief
            void EnqOverlapped (
                std::unique_ptr<Overlapped> overlapped,
                std::list<std::unique_ptr<Overlapped>> &list,
                bool front = false);
            /// \brief
            /// Called by PumpAsyncIo to remove the head buffer from the given list.
            /// \param[in, out] list List of overlappeds to return the head overlapped from.
            /// \return Head overlapped from the given list.
            std::unique_ptr<Overlapped> DeqOverlapped (std::list<std::unique_ptr<Overlapped>> &list);
            /// \brief
            /// Called by \see{Stream::HandleAsyncEvent} when processing
            /// the EventWrite, EventWriteTo and EventWriteMsg events.
            /// Writes the pending buffers to the stream.
            std::unique_ptr<Overlapped> PumpAsyncIo (std::list<std::unique_ptr<Overlapped>> &list);
        #endif // !defined (TOOLCHAIN_OS_Windows)

            virtual std::size_t ReadHelper (
                void *buffer,
                std::size_t count) override;
            virtual std::size_t WriteHelper (
                const void *buffer,
                std::size_t count) override;

            /// \brief
            /// \see{AsyncIoEventQueue} needs access to the events.
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
        #define THEKOGANS_STREAM_DECLARE_STREAM(type)\
            THEKOGANS_UTIL_DECLARE_REF_COUNTED_POINTERS (type)\
            THEKOGANS_UTIL_DECLARE_HEAP_WITH_LOCK (type, thekogans::util::SpinLock)\
            THEKOGANS_STREAM_DISALLOW_COPY_AND_ASSIGN (type)

        /// \def THEKOGANS_STREAM_IMPLEMENT_STREAM_COMMON(type)
        /// This macro is used in the stream definition file (.cpp).
        /// It sets up everything needed for the stream to be dynamically
        /// discoverable, and creatable.
        /// \param[in] type Stream class name.
        #define THEKOGANS_STREAM_IMPLEMENT_STREAM(type)\
            THEKOGANS_UTIL_IMPLEMENT_HEAP_WITH_LOCK (type, thekogans::util::SpinLock)

    } // namespace stream
} // namespace thekogans

#endif // !defined (__thekogans_stream_Stream_h)
