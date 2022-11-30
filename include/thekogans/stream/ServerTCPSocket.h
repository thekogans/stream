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
            virtual void OnServerTCPSocketConnection (
                util::RefCounted::SharedPtr<ServerTCPSocket> serverTCPSocket,
                TCPSocket::SharedPtr connection) throw ();
        };

        /// \struct ServerTCPSocket ServerTCPSocket.h thekogans/stream/ServerTCPSocket.h
        ///
        /// \brief
        /// ServerTCPSocket is used to listen for connections from \see{ClientTCPSockets}.
        ///
        /// Ex:
        /// \code{.cpp}
        /// using namespace thekogans;
        ///
        /// struct Server :
        ///         public util::Singleton<
        ///             Server,
        ///             util::SpinLock,
        ///             util::RefCountedInstanceCreator<Server>,
        ///             util::RefCountedInstanceDestroyer<Server>>,
        ///         public util::Subscriber<ServerTCPSocketEvents> {
        /// private:
        ///     stream::Address &address;
        ///     stream::ServerTCPSocket serverSocket;
        ///     std::vector<TCPSocket::SharedPtr> connections;
        ///     util::JobQueue jobQueue;
        ///
        /// public:
        ///     void Start (const stream::Address &address_) {
        ///         address = address_;
        ///         AcceptClientConnections ();
        ///     }
        ///
        ///     void Stop () {
        ///         clientSocket.Reset ();
        ///         connections.clear ();
        ///     }
        ///
        /// private:
        ///     void OnStreamError (
        ///             stream::SharedPtr stream,
        ///             const util::Exception &exception) throw () {
        ///         // Log exception.
        ///         if (serverSocket == stream) {
        ///             AcceptClientConnections ();
        ///         }
        ///         else {
        ///             std::vector<TCPSocket::SharedPtr>::iterator it =
        ///                 std::find (connections.begin (), connections.end (), stream);
        ///             if (it != connections.end ()) {
        ///                 connections.erase (it);
        ///             }
        ///         }
        ///     }
        ///
        ///     void OnStreamDisconnect (Stream::SharedPtr stream) throw () {
        ///         std::vector<TCPSocket::SharedPtr>::iterator it =
        ///             std::find (connections.begin (), connections.end (), stream);
        ///         if (it != connections.end ()) {
        ///             connections.erase (it);
        ///         }
        ///     }
        ///
        ///     void OnStreamRead (
        ///             stream::SharedPtr stream,
        ///             util::Buffer buffer) throw () {
        ///         // Process incomming request from a client.
        ///     }
        ///
        ///     void OnServerTCPSocketConnection (
        ///             stream::ServerTCPSocket::SharedPtr /*serverTCPSocket*/,
        ///             stream::TCPSocket::SharedPtr connection) throw () {
        ///         // Log new connection.
        ///         connection->MakeAsync ();
        ///         util::Subscriber<stream::StreamEvents>::Subscribe (
        ///             *connection,
        ///             util::Producer<stream::StreamEvents>::EventDeliveryPolicy::SharedPtr (
        ///                 new util::Producer<stream::StreamEvents>::RunLoopEventDeliveryPolicy (
        ///                     jobQueue)));
        ///         // Initiate an async read to listen for client requests.
        ///         connection->Read ();
        ///         connections.push_back (connection);
        ///     }
        ///
        ///     void AcceptClientConnections () {
        ///         connections.clear ();
        ///         serverSocket.Reset (new stream::ServerTCPSocket (address));
        ///         serverSocket->MakeAsync ();
        ///         util::Subscriber<stream::StreamEvents>::Subscribe (
        ///             *serverSocket,
        ///             util::Producer<stream::StreamEvents>::EventDeliveryPolicy::SharedPtr (
        ///                 new util::Producer<stream::StreamEvents>::RunLoopEventDeliveryPolicy (
        ///                     jobQueue)));
        ///         util::Subscriber<stream::ServerTCPSocketEvents>::Subscribe (
        ///             *serverSocket,
        ///             util::Producer<stream::ServerTCPSocketEvents>::EventDeliveryPolicy::SharedPtr (
        ///                 new util::Producer<stream::ServerTCPSocketEvents>::RunLoopEventDeliveryPolicy (
        ///                     jobQueue)));
        ///         serverSocket->Accept ();
        ///     }
        /// };
        /// \endcode

        struct _LIB_THEKOGANS_STREAM_DECL ServerTCPSocket :
                public TCPSocket,
                public util::Producer<ServerTCPSocketEvents> {
            /// \brief
            /// ServerTCPSocket participates in the Stream dynamic
            /// discovery and creation.
            THEKOGANS_STREAM_DECLARE_STREAM (ServerTCPSocket)

            /// \brief
            /// ctor.
            /// Wrap an OS handle.
            /// \param[in] handle OS stream handle to wrap.
            ServerTCPSocket (THEKOGANS_UTIL_HANDLE handle = THEKOGANS_UTIL_INVALID_HANDLE_VALUE) :
                TCPSocket (handle) {}
            /// \brief
            /// ctor.
            /// \param[in] family Socket family specification.
            /// \param[in] type Socket type specification.
            /// \param[in] protocol Socket protocol specification.
            ServerTCPSocket (
                int family,
                int type,
                int protocol) :
                TCPSocket (family, type, protocol) {}
            /// \brief
            /// ctor.
            /// \param[in] address Address to listen on.
            /// \param[in] reuseAddress Call \see{Socket::SetReuseAddress} with this parameter.
            /// \param[in] maxPendingConnections Max pending connection requests.
            ServerTCPSocket (
                const Address &address,
                bool reuseAddress = false,
                util::ui32 maxPendingConnections = TCPSocket::DEFAULT_MAX_PENDING_CONNECTIONS);

            // Stream
            /// \brief
            /// Stop listenning for connection requests.
            virtual void Disconnect () {
                Stream::Disconnect ();
            }

            /// \brief
            /// Wait for connections.
            /// NOTE: This api can only be used by blocking (not async) sockets.
            /// Async sockets go in to listening mode as soon as you add them to
            /// an AsyncIoEventQueue, and return new connections through
            /// AsyncIoEventSink::HandleServerTCPSocketConnection.
            /// \return The new connection.
            TCPSocket::SharedPtr Accept ();

        protected:
            // Stream
            /// \brief
            /// ServerTCPSocket only listens for connections.
            virtual std::size_t Read (
                    void * /*buffer*/,
                    std::size_t /*count*/) {
                assert (0);
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "%s", "ServerTCPSocket can't Read.");
                return -1;
            }
            /// \brief
            /// ServerTCPSocket only listens for connections.
            virtual std::size_t Write (
                    const void * /*buffer*/,
                    std::size_t /*count*/) {
                assert (0);
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "%s", "ServerTCPSocket can't Write.");
                return -1;
            }
            /// \brief
            /// ServerTCPSocket only listens for connections.
            virtual void WriteBuffer (
                    util::Buffer /*buffer*/) {
                assert (0);
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "%s", "ServerTCPSocket can't WriteBuffer.");
            }

        #if defined (TOOLCHAIN_OS_Windows)
            /// \brief
            /// Used by AsyncIoEventQueue to notify the stream that
            /// an overlapped operation has completed successfully.
            /// \param[in] overlapped Overlapped that completed successfully.
            virtual void HandleOverlapped (AsyncInfo::Overlapped &overlapped) throw ();
        #else // defined (TOOLCHAIN_OS_Windows)
            /// \brief
            /// Used by AsyncIoEventQueue to notify the stream of
            /// pending io events.
            /// \param[in] events \see{AsyncIoEventQueue} events enum.
            virtual void HandleAsyncEvent (util::ui32 event) throw ();
        #endif // defined (TOOLCHAIN_OS_Windows)

            /// \brief
            /// Streams are neither copy constructable, nor assignable.
            THEKOGANS_STREAM_DISALLOW_COPY_AND_ASSIGN (ServerTCPSocket)
        };

    } // namespace stream
} // namespace thekogans

#endif // !defined (__thekogans_stream_ServerTCPSocket_h)
