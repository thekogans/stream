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

#if !defined (__thekogans_stream_ClientNamedPipe_h)
#define __thekogans_stream_ClientNamedPipe_h

#include "thekogans/util/Environment.h"

#if defined (TOOLCHAIN_OS_Windows)

#include "pugixml/pugixml.hpp"
#include "thekogans/stream/Config.h"
#include "thekogans/stream/NamedPipe.h"
#include "thekogans/stream/Address.h"

namespace thekogans {
    namespace stream {

        struct ClientNamedPipe;

        struct _LIB_THEKOGANS_STREAM_DECL ClientNamedPipeEvents : public virtual util::RefCounted {
            /// \brief
            /// Declare \see{util::RefCounted} pointers.
            THEKOGANS_UTIL_DECLARE_REF_COUNTED_POINTERS (ClientNamedPipeEvents)

            /// \brief
            /// dtor.
            virtual ~ClientNamedPipeEvents () {}

            /// \brief
            /// Called to report a connection on a \see{ClientNamedPipe}.
            /// \param[in] clientNamedPipe \see{ClientNamedPipe} on which
            /// the connection occurred.
            virtual void OnClientNamedPipeConnected (
                util::RefCounted::SharedPtr<ClientNamedPipe> clientNamedPipe) throw ();
        };

        /// \struct ClientNamedPipe ClientNamedPipe.h thekogans/stream/ClientNamedPipe.h
        ///
        /// \brief
        /// Client side named pipe. Use this class to connect to
        /// \see{ServerNamedPipe} instances. ClientNamedPipe can
        /// be either stream or datagram just like sockets.

        struct _LIB_THEKOGANS_STREAM_DECL ClientNamedPipe :
                public NamedPipe,
                public util::Producer<ClientNamedPipeEvents> {
            /// \brief
            /// ClientNamedPipe participates in the Stream dynamic
            /// discovery and creation.
            THEKOGANS_STREAM_DECLARE_STREAM (ClientNamedPipe)

            enum {
                /// \brief
                /// Default timeout while waiting to connect (30 seconds).
                DEFAULT_TIMEOUT = 30000
            };

        private:
            /// \brief
            /// Address to listen on.
            Address address;
            /// \brief
            /// Pipe type (Byte/Message).
            PipeType pipeType;

        public:
            /// \brief
            /// ctor.
            /// Wrap an OS handle.
            /// \param[in] handle OS stream handle to wrap.
            ClientNamedPipe (THEKOGANS_UTIL_HANDLE handle = THEKOGANS_UTIL_INVALID_HANDLE_VALUE) :
                NamedPipe (handle) {}
            /// \brief
            /// ctor.
            /// Create a ClientNamedPipe and connect to the
            /// ServerNamedPipe at the other end of the address.
            /// \param[in] address Address of ServerNamedPipe to connect to.
            /// \param[in] pipeType Byte/Message (similar to Socket/UDPSocket).
            ClientNamedPipe (
                const Address &address_,
                PipeType pipeType_ = Byte) :
                address (address_),
                pipeType (pipeType_) {}

            /// \brief
            /// Wait for a server side instance of the pipe to become available for connecting.
            /// \param[in] timeout How long to wait for connection before giving up.
            bool Wait (DWORD timeout);

            /// \brief
            /// Connect to the ServerNamedPipe at the other end of the address.
            /// NOTE: Client named pipes cannot connect to the server asynchronously.
            /// Therefore you must call this function before calling \see{AsyncIoEventQueue::AddStream}.
            /// If you do make the pipe async after calling Connect, the pipe will deliver
            /// an \see{AsyncIoEventSink::HandleClientNamedPipeConnected} to simulate an
            /// async connection.
            /// \param[in] securityAttributes Optional pointer to SECURITY_ATTRIBUTES.
            void Connect (LPSECURITY_ATTRIBUTES securityAttributes = 0);

        protected:
            /// \brief
            /// Used by the \see{AsyncIoEventQueue} to allow the stream to
            /// initialize itself. When this function is called, the
            /// stream is already async, and Stream::AsyncInfo has
            /// been created. At this point the stream should do
            /// whatever stream specific initialization it needs to
            /// do.
            virtual void InitAsyncIo ();
            /// \brief
            /// Used by \see{AsyncIoEventQueue} to notify the stream that
            /// an overlapped operation has completed successfully.
            /// \param[in] overlapped Overlapped that completed successfully.
            virtual void HandleOverlapped (AsyncInfo::Overlapped &overlapped) throw ();
        };

    } // namespace stream
} // namespace thekogans

#endif // defined (TOOLCHAIN_OS_Windows)

#endif // !defined (__thekogans_stream_ClientNamedPipe_h)
