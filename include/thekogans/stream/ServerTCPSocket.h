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

#if !defined (__thekogans_stream_ServerTCPSocket_h)
#define __thekogans_stream_ServerTCPSocket_h

#include <memory>
#include <string>
#include "pugixml/pugixml.hpp"
#include "thekogans/util/Environment.h"
#include "thekogans/util/Types.h"
#include "thekogans/stream/Config.h"
#include "thekogans/stream/TCPSocket.h"

namespace thekogans {
    namespace stream {

        struct ServerTCPSocket;

        struct _LIB_THEKOGANS_STREAM_DECL ServerTCPSocketEvents : public virtual util::RefCounted {
            /// \brief
            /// Declare \see{util::RefCounted} pointers.
            THEKOGANS_UTIL_DECLARE_REF_COUNTED_POINTERS (ServerTCPSocketEvents)

            /// \brief
            /// dtor.
            virtual ~ServerTCPSocketEvents () {}

            /// \brief
            /// Called to report a new connection on a \see{ServerTCPSocket}.
            /// \param[in] serverTCPSocket \see{ServerTCPSocket} on which the
            /// new connection occurred.
            /// \param[in] connection The new connection socket.
            /// NOTE: The new connection will be sync (blocking).
            virtual void HandleServerTCPSocketConnection (
                util::RefCounted::SharedPtr<ServerTCPSocket> serverTCPSocket,
                TCPSocket::SharedPtr connection) throw ();
        };

        /// \struct ServerTCPSocket ServerTCPSocket.h thekogans/stream/ServerTCPSocket.h
        ///
        /// \brief
        /// ServerTCPSocket is used to listen for connections from \see{ClientTCPSockets}.

        struct _LIB_THEKOGANS_STREAM_DECL ServerTCPSocket :
                public TCPSocket,
                public thekogans::util::Producer<StreamEvents>,
                public thekogans::util::Producer<ServerTCPSocketEvents> {
            /// \brief
            /// ServerTCPSocket participates in the Stream dynamic
            /// discovery and creation.
            THEKOGANS_STREAM_DECLARE_STREAM (ServerTCPSocket)

            /// \brief
            /// ctor.
            /// \param[in] address Address to listen on.
            /// \param[in] reuseAddress Call \see{Socket::SetReuseAddress} with this parameter.
            /// \param[in] maxPendingConnections Max pending connection requests.
            ServerTCPSocket (
                const Address &address,
                bool reuseAddress = false,
                util::ui32 maxPendingConnections = TCPSocket::DEFAULT_MAX_PENDING_CONNECTIONS);

            /// \brief
            /// Listening for incoming connections is pretty
            /// much the only trick ServerTCPSocket knows.
            /// Call this method after creating the server
            /// socket when you're ready to start receiving
            /// connections.
            void ListenForConnections ();

        protected:
            /// \brief
            /// Override this method if you're deriving from a TCPSocket.
            /// \param[in] handle OS socket handle to wrap.
            /// \return A \see{TCPSocket} derivative.
            virtual TCPSocket::SharedPtr GetTCPSocket (THEKOGANS_UTIL_HANDLE handle) {
                return TCPSocket::SharedPtr (new TCPSocket (handle));
            }

            /// \brief
            /// ServerTCPSocket only listens for connections.
            virtual void Write (
                    const void * /*buffer*/,
                    std::size_t /*count*/) override {
                assert (0);
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "%s", "ServerTCPSocket can't Write.");
                return -1;
            }
            /// \brief
            /// ServerTCPSocket only listens for connections.
            virtual void WriteBuffer (
                    util::Buffer /*buffer*/) override {
                assert (0);
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "%s", "ServerTCPSocket can't WriteBuffer.");
            }

        #if defined (TOOLCHAIN_OS_Windows)
            /// \brief
            /// Used by AsyncIoEventQueue to notify the stream that
            /// an overlapped operation has completed successfully.
            /// \param[in] overlapped Overlapped that completed successfully.
            virtual void HandleOverlapped (Overlapped &overlapped) throw () override;
        #else // defined (TOOLCHAIN_OS_Windows)
            /// \brief
            /// Used by AsyncIoEventQueue to notify the stream of
            /// pending io events.
            /// \param[in] events \see{AsyncIoEventQueue} events enum.
            virtual void HandleAsyncEvent (util::ui32 event) throw () override;
        #endif // defined (TOOLCHAIN_OS_Windows)

            /// \brief
            /// Streams are neither copy constructable, nor assignable.
            THEKOGANS_STREAM_DISALLOW_COPY_AND_ASSIGN (ServerTCPSocket)
        };

    } // namespace stream
} // namespace thekogans

#endif // !defined (__thekogans_stream_ServerTCPSocket_h)
