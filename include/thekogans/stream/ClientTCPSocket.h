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

#if !defined (__thekogans_stream_ClientTCPSocket_h)
#define __thekogans_stream_ClientTCPSocket_h

#include <string>
#include "pugixml/pugixml.hpp"
#include "thekogans/util/Types.h"
#include "thekogans/stream/Config.h"
#include "thekogans/stream/TCPSocket.h"

namespace thekogans {
    namespace stream {

        struct _LIB_THEKOGANS_STREAM_DECL TCPSocketEvents : public virtual util::RefCounted {
            /// \brief
            /// Declare \see{util::RefCounted} pointers.
            THEKOGANS_UTIL_DECLARE_REF_COUNTED_POINTERS (TCPSocketEvents)

            /// \brief
            /// dtor.
            virtual ~TCPSocketEvents () {}

            /// \brief
            /// Called when a client \see{TCPSocket} has established
            /// a connection to the server.
            /// \param[in] tcpSocket \see{TCPSocket} that established
            /// a connection.
            virtual void OnTCPSocketConnected (
                util::RefCounted::SharedPtr<TCPSocket> tcpSocket) throw () {}
        };

        /// \struct ClientTCPSocket ClientTCPSocket.h thekogans/stream/ClientTCPSocket.h
        ///
        /// \brief
        /// ClientTCPSocket exposes an Context you can use to create client
        /// side TCPSocket from rest. Use it to instantiate a TCPSocket from
        /// a configuration file. Other than that, ClientTCPSocket defers to
        /// TCPSocket. (as a mater of fact, ClientTCPSocket::Context::CreateStream
        /// creates \see{TCPSocket} and not a ClientTCPSocket!
        ///
        /// Ex:
        /// \code{.cpp}
        /// using namespace thekogans;
        ///
        /// struct Client :
        ///         public util::Singleton<
        ///             Client,
        ///             util::SpinLock,
        ///             util::RefCountedInstanceCreator<Client>,
        ///             util::RefCountedInstanceDestroyer<Client>>,
        ///         public util::Subscriber<ClientTCPSocketEvents> {
        /// private:
        ///     stream::Address &address;
        ///     stream::ClientTCPSocket clientSocket;
        ///     util::JobQueue jobQueue;
        ///
        /// public:
        ///     void Start (const stream::Address &address_) {
        ///         address = address_;
        ///         ConnectToServer ();
        ///     }
        ///
        ///     void Stop () {
        ///         clientSocket.Reset ();
        ///     }
        ///
        /// private:
        ///     // StreamEvents
        ///     void OnStreamError (
        ///             Stream::SharedPtr /*stream*/,
        ///             const util::Exception &exception) throw () {
        ///         // Log exception.
        ///         ConnectToServer ();
        ///     }
        ///
        ///     void OnStreamDisconnect (
        ///             Stream::SharedPtr /*stream*/) throw () {
        ///         ConnectToServer ();
        ///     }
        ///
        ///     void Client::OnStreamRead (
        ///             Stream::SharedPtr stream,
        ///             util::Buffer buffer) throw () {
        ///         // Process incomming reply from the server.
        ///     }
        ///
        ///     // ClientTCPSocketEvents
        ///     void Client::OnClientTCPSocketConnected (
        ///             TCPSocket::SharedPtr tcpSocket) throw () {
        ///         // Send handshake packet(s).
        ///         tcpSocket->Read ();
        ///     }
        ///
        ///     void Client::ConnectToServer () {
        ///         clientSocket.Reset (new stream::ClientTCPSocket);
        ///         clientSocket->MakeAsync ();
        ///         util::Subscriber<stream::StreamEvents>::Subscribe (
        ///             *clientSocket,
        ///             util::Producer<stream::StreamEvents>::EventDeliveryPolicy::SharedPtr (
        ///                 new util::Producer<stream::StreamEvents>::RunLoopEventDeliveryPolicy (
        ///                     jobQueue)));
        ///         util::Subscriber<stream::ClientTCPSocketEvents>::Subscribe (
        ///             *clientSocket,
        ///             util::Producer<stream::ClientTCPSocketEvents>::EventDeliveryPolicy::SharedPtr (
        ///                 new util::Producer<stream::ClientTCPSocketEvents>::RunLoopEventDeliveryPolicy (
        ///                     jobQueue)));
        ///         clientSocket->Connect (address);
        ///     }
        /// };
        /// \endcode

        struct _LIB_THEKOGANS_STREAM_DECL ClientTCPSocket :
                public TCPSocket,
                public util::Producer<ClientTCPSocketEvents> {
            /// \brief
            /// ClientTCPSocket participates in the \see{Stream} dynamic
            /// discovery and creation.
            THEKOGANS_STREAM_DECLARE_STREAM (ClientTCPSocket)

            /// \brief
            /// ctor.
            /// Wrap an OS handle.
            /// \param[in] handle OS stream handle to wrap.
            ClientTCPSocket (THEKOGANS_UTIL_HANDLE handle = THEKOGANS_UTIL_INVALID_HANDLE_VALUE) :
                TCPSocket (handle) {}
            /// \brief
            /// ctor.
            /// \param[in] family Socket family specification.
            /// \param[in] type Socket type specification.
            /// \param[in] protocol Socket protocol specification.
            ClientTCPSocket (
                int family,
                int type,
                int protocol) :
                TCPSocket (family, type, protocol) {}

            /// \brief
            /// Connect to a host with the given address.
            /// \param[in] address Address of host to connect to.
            void Connect (const Address &address);

            /// \brief
            /// Streams are neither copy constructable, nor assignable.
            THEKOGANS_STREAM_DISALLOW_COPY_AND_ASSIGN (ClientTCPSocket)
        };

    } // namespace stream
} // namespace thekogans

#endif // !defined (__thekogans_stream_ClientTCPSocket_h)
