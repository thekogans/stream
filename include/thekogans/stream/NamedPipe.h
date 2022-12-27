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

#if !defined (__thekogans_stream_NamedPipe_h)
#define __thekogans_stream_NamedPipe_h

#include "thekogans/util/Environment.h"

#if defined (TOOLCHAIN_OS_Windows)

#if !defined (_WINDOWS_)
    #if !defined (WIN32_LEAN_AND_MEAN)
        #define WIN32_LEAN_AND_MEAN
    #endif // !defined (WIN32_LEAN_AND_MEAN)
    #if !defined (NOMINMAX)
        #define NOMINMAX
    #endif // !defined (NOMINMAX)
    #include <windows.h>
#endif // !defined (_WINDOWS_)
#include "thekogans/stream/Config.h"
#include "thekogans/stream/Stream.h"

namespace thekogans {
    namespace stream {

        struct NamedPipe;

        struct _LIB_THEKOGANS_STREAM_DECL NamedPipeEvents : public virtual util::RefCounted {
            /// \brief
            /// Declare \see{util::RefCounted} pointers.
            THEKOGANS_UTIL_DECLARE_REF_COUNTED_POINTERS (NamedPipeEvents)

            /// \brief
            /// dtor.
            virtual ~NamedPipeEvents () {}

            /// \brief
            /// Called to report a connection on a \see{ServerNamedPipe}.
            /// \param[in] namedPipe \see{NamedPipe} on which the connection occurred.
            virtual void OnNamedPipeAccept (
                util::RefCounted::SharedPtr<NamedPipe> namedPipe) throw ();
        }

        /// \struct NamedPipe NamedPipe.h thekogans/stream/NamedPipe.h
        ///
        /// \brief

        struct _LIB_THEKOGANS_STREAM_DECL NamedPipe :
                public Stream,
                public util::Producer<NamedPipeEvents> {
            /// \enum
            /// Named pipe types.
            enum PipeType {
                /// \brief
                /// Create a stream named pipe.
                Byte,
                /// \brief
                /// Create a datagram named pipe.
                Message
            };

            /// \brief
            /// ctor.
            /// Wrap an OS handle.
            /// \param[in] handle OS stream handle to wrap.
            NamedPipe (THEKOGANS_UTIL_HANDLE handle) :
                Stream (handle) {}
            /// \brief
            /// ctor.
            /// Create a server side named pipe.
            /// \param[in] address_ \see{Address} to listen on.
            /// \param[in] pipeType_ Byte/Message (similar to Socket/ServerNamedPipe).
            /// \param[in] bufferSize_ Size of receive buffer.
            /// NOTE: If you plan on using the ServerNamedPipe asynchronously,
            /// there is no need to call ServerNamedPipe::Connect, as
            /// AsyncIoEventQueue::AddStream will do that for you.
            NamedPipe (
                const Address &address_,
                PipeType pipeType_ = Byte);
            /// \brief
            /// ctor.
            /// Create a ClientNamedPipe and connect to the
            /// ServerNamedPipe at the other end of the address.
            /// \param[in] address Address of ServerNamedPipe to connect to.
            /// \param[in] pipeType Byte/Message (similar to Socket/UDPSocket).
            NamedPipe (
                const Address &address_,
                PipeType pipeType_ = Byte,
                LPSECURITY_ATTRIBUTES securityAttributes = 0) :
                address (address_),
                pipeType (pipeType_) {}

            // Stream
            /// \brief
            /// Return number of bytes available for reading.
            /// \return Number of bytes available for reading.
            virtual std::size_t GetDataAvailable () const override;
            /// \brief
            /// Read bytes from the stream.
            /// \param[in] bufferLength Buffer length for async WSARecv[From | Msg].
            virtual void Read (std::size_t bufferLength = DEFAULT_BUFFER_LENGTH) override;
            /// \brief
            /// Write buffer the stream.
            /// \param[in] buffer Buffer to write.
            virtual void Write (util::Buffer buffer) override;

            /// \brief
            /// Listen for an incoming connection.
            void Accept ();

            /// \brief
            /// Disconnect the client end of the named pipe.
            /// \param[in] flushBuffers Call FlushFileBuffers before disconnecting.
            void Disconnect (bool flushBuffers = true);

            /// \brief
            /// Wait for a server side instance of the pipe to become available for connecting.
            /// \param[in] timeout How long to wait for connection before giving up.
            bool Wait (DWORD timeout);

            /// \brief
            /// Clone this ServerNamedPipe.
            /// \return Cloned ServerNamedPipe.
            NamedPipe::SharedPtr Clone () const;

        protected:
            // Stream
            /// \brief
            /// Used by AsyncIoEventQueue to notify the stream that
            /// an overlapped operation has completed successfully.
            /// \param[in] overlapped Overlapped that completed successfully.
            virtual void HandleOverlapped (Overlapped &overlapped) throw () override;

            virtual std::size_t ReadHelper (
                void *buffer,
                std::size_t count) override;
            virtual std::size_t WriteHelper (
                const void *buffer,
                std::size_t count) override;
        };

    } // namespace stream
} // namespace thekogans

#endif // defined (TOOLCHAIN_OS_Windows)

#endif // !defined (__thekogans_stream_NamedPipe_h)
