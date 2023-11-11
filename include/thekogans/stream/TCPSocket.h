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

#if !defined (__thekogans_stream_TCPSocket_h)
#define __thekogans_stream_TCPSocket_h

#include "thekogans/util/Environment.h"
#include "thekogans/util/Constants.h"
#include "thekogans/util/SpinLock.h"
#include "thekogans/util/Exception.h"
#include "thekogans/stream/Config.h"
#include "thekogans/stream/Socket.h"

namespace thekogans {
    namespace stream {

        /// \brief
        /// Forward declaration of \see{TCPSocket}.
        struct TCPSocket;

        /// \struct TCPSocketEvents TCPSocket.h thekogans/stream/TCPSocket.h
        ///
        /// \brief
        /// Subscribe to TCPSocketEvents to receive \see{TCPSocket} event notifications.

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
            /// \param[in] adress \see{Address} the client connected on.
            virtual void OnTCPSocketConnect (
                util::RefCounted::SharedPtr<TCPSocket> /*tcpSocket*/,
                const Address & /*address*/) throw () {}
            /// \brief
            /// Called to report a new connection on a \see{TCPSocket}.
            /// \param[in] tcpSocket \see{TCPSocket} on which the new connection occurred.
            /// \param[in] connection The new connection socket.
            virtual void OnTCPSocketAccept (
                util::RefCounted::SharedPtr<TCPSocket> /*tcpSocket*/,
                util::RefCounted::SharedPtr<TCPSocket> /*connection*/) throw () {}
        };

        /// \struct TCPSocket TCPSocket.h thekogans/stream/TCPSocket.h
        ///
        /// \brief
        /// TCPSocket is a base class for all SOCK_STREAM socket derivatives.
        /// It provides all common SOCK_STREAM socket apis, and let's the
        /// derivatives handle the specifics.
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
        ///         public util::Subscriber<StreamEvents>,
        ///         public util::Subscriber<TCPSocketEvents> {
        /// private:
        ///     stream::Address address;
        ///     stream::TCPSocket::SharedPtr clientSocket;
        ///
        /// public:
        ///     void Start (const stream::Address &address_) {
        ///         address = address_;
        ///         ResetIo (true);
        ///     }
        ///
        ///     void Stop () {
        ///         ResetIo (false);
        ///     }
        ///
        /// private:
        ///     // StreamEvents
        ///     virtual void OnStreamError (
        ///             Stream::SharedPtr /*stream*/,
        ///             const util::Exception &exception) throw () override {
        ///         // Log exception.
        ///         ResetIo (true);
        ///     }
        ///
        ///     virtual void OnStreamDisconnect (Stream::SharedPtr /*stream*/) throw () override {
        ///         // stream disconnected.
        ///     }
        ///
        ///     virtual void OnStreamRead (
        ///             Stream::SharedPtr stream,
        ///             const util::Buffer &buffer) throw () override {
        ///         // Process incomming reply from the server.
        ///     }
        ///
        ///     // TCPSocketEvents
        ///     virtual void OnTCPSocketConnect (TCPSocket::SharedPtr tcpSocket) throw () override {
        ///         // Send handshake packet(s).
        ///         // Post an async read to get the servers response.
        ///         tcpSocket->Read (0);
        ///     }
        ///
        ///     void ResetIo (bool connect) {
        ///         // Given the nature of async io, there are no guarantees that the clientSocket.Reset (...)
        ///         // call below will result in the pointer being deleted. There might be residual references
        ///         // due to other threads in the code still working with the object. It is therefore
        ///         // imperative that we sever all communications with the old producer before creating a new one.
        ///         // Stream contamination is a dangerous thing.
        ///         util::Subscriber<stream::StreamEvents>::Unsubscribe ();
        ///         util::Subscriber<stream::TCPSocketEvents>::Unsubscribe ();
        ///         clientSocket.Reset ();
        ///         if (connect) {
        ///             // Create a new client socket.
        ///             clientSocket.Reset (new stream::TCPSocket (AF_INET, SOCK_STREAM, 0));
        ///             // Setup async notifications.
        ///             // NOTE: We use the default EventDeliveryPolicy (ImmediateEventDeliveryPolicy).
        ///             // The reason for this is explained in \see{Stream}.
        ///             util::Subscriber<stream::StreamEvents>::Subscribe (*clientSocket);
        ///             util::Subscriber<stream::TCPSocketEvents>::Subscribe (*clientSocket);
        ///             // The socket is now async. All appropriate notification channels are open.
        ///             // Fire up a connect attempt.
        ///             clientSocket->Connect (address);
        ///         }
        ///     }
        /// };
        /// \endcode
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
        ///         public util::Subscriber<StreamEvents>, {
        ///         public util::Subscriber<TCPSocketEvents> {
        /// private:
        ///     stream::Address address;
        ///     bool reuseAddress;
        ///     util::ui32 maxPendingConnections;
        ///     stream::TCPSocket::SharedPtr serverSocket;
        ///     std::vector<TCPSocket::SharedPtr> connections;
        ///
        /// public:
        ///     void Start (
        ///             const stream::Address &address_,
        ///             bool reuseAddress_ = false,
        ///             util::ui32 maxPendingConnections_ = TCPSocket::DEFAULT_MAX_PENDING_CONNECTIONS) {
        ///         address = address_;
        ///         reuseAddress = reuseAddress_;
        ///         maxPendingConnections = maxPendingConnections_;
        ///         ResetIo (true);
        ///     }
        ///
        ///     void Stop () {
        ///         ResetIo (false);
        ///     }
        ///
        /// private:
        ///     // StreamEvents
        ///     virtual void OnStreamError (
        ///             stream::Stream::SharedPtr stream,
        ///             const util::Exception &exception) throw () override {
        ///         // Log exception.
        ///         // Both serverSocket and connections will wind up here in case of error.
        ///         // If it's a connection, remove it from the list.
        ///         if (stream != serverSocket) {
        ///             RemoveConnection (stream);
        ///         }
        ///     }
        ///
        ///     virtual void OnStreamDisconnect (stream::Stream::SharedPtr stream) throw () override {
        ///         RemoveConnection (stream);
        ///     }
        ///
        ///     virtual void OnStreamRead (
        ///             stream::Stream::SharedPtr stream,
        ///             const util::Buffer &buffer) throw () override {
        ///         // Process incomming request from a client.
        ///     }
        ///
        ///     // TCPSocketEvents
        ///     virtual void OnTCPSocketAccept (
        ///             stream::TCPSocket::SharedPtr /*tcpSocket*/,
        ///             stream::TCPSocket::SharedPtr connection) throw () override {
        ///         // Setup async notifications.
        ///         // NOTE: We use the default EventDeliveryPolicy (ImmediateEventDeliveryPolicy).
        ///         // The reason for this is explained in \see{Stream}.
        ///         util::Subscriber<stream::StreamEvents>::Subscribe (*connection);
        ///         // Initiate an async read to listen for client requests.
        ///         connection->Read (0);
        ///         connections.push_back (connection);
        ///     }
        ///
        ///     void ResetIo (bool accept) {
        ///         // Given the nature of async io, there are no guarantees that the connections.clear () and
        ///         // serverSocket.Reset (...) calls below will result in the pointers being deleted. There might
        ///         // be residual references on the objects just due to other threads in the code still doing some
        ///         // work. It is therefore imperative that we sever all communications with the old producers before
        ///         // connecting new ones. Stream contamination is a dangerous thing.
        ///         util::Subscriber<stream::StreamEvents>::Unsubscribe ();
        ///         util::Subscriber<stream::TCPSocketEvents>::Unsubscribe ();
        ///         connections.clear ();
        ///         serverSocket.Reset ();
        ///         if (accept) {
        ///             // Create a listening socket.
        ///             serverSocket.Reset (new stream::TCPSocket (address, reuseAddress, maxPendingConnections));
        ///             // Setup async notifications.
        ///             // NOTE: We use the default EventDeliveryPolicy (ImmediateEventDeliveryPolicy).
        ///             // The reason for this is explained in \see{Stream}.
        ///             util::Subscriber<stream::StreamEvents>::Subscribe (*serverSocket);
        ///             util::Subscriber<stream::TCPSocketEvents>::Subscribe (*serverSocket);
        ///             // We're open for business. Start listening for client connections.
        ///             serverSocket->Accept ();
        ///         }
        ///     }
        ///
        ///     void RemoveConnection (Stream::SharedPtr stream) {
        ///         std::vector<TCPSocket::SharedPtr>::iterator it =
        ///             std::find (
        ///                 connections.begin (),
        ///                 connections.end (),
        ///                 util::dynamic_refcounted_sharedptr_cast<TCPSocket> (stream));
        ///         if (it != connections.end ()) {
        ///             util::Subscriber<stream::StreamEvents>::Unsubscribe (**it);
        ///             connections.erase (it);
        ///         }
        ///     }
        /// };
        /// \endcode

        struct _LIB_THEKOGANS_STREAM_DECL TCPSocket :
                public Socket,
                public util::Producer<TCPSocketEvents> {
            /// \brief
            /// TCPSocket is a \see{Stream}.
            THEKOGANS_STREAM_DECLARE_STREAM (TCPSocket)

            /// \brief
            /// ctor.
            /// Wrap an OS handle.
            /// \param[in] handle OS stream handle to wrap.
            explicit TCPSocket (THEKOGANS_UTIL_HANDLE handle) :
                Socket (handle) {}
            /// \brief
            /// ctor.
            /// \param[in] family Address family specification.
            /// \param[in] type Socket type specification.
            /// \param[in] protocol Socket protocol specification.
            TCPSocket (
                int family,
                int type,
                int protocol) :
                Socket (family, type, protocol) {}
            enum {
                /// \brief
                /// Default max pending connection requests.
                DEFAULT_MAX_PENDING_CONNECTIONS = 5
            };
            /// \brief
            /// ctor.
            /// \param[in] address Address to listen on.
            /// \param[in] reuseAddress Call \see{Socket::SetReuseAddress} with this parameter.
            /// \param[in] maxPendingConnections Maximum number of waiting connections.
            TCPSocket (
                const Address &address,
                bool reuseAddress = false,
                util::i32 maxPendingConnections = DEFAULT_MAX_PENDING_CONNECTIONS);

            /// \brief
            /// Return true if Connect was successfully called on this socket.
            /// \return true if Connect was successfully called on this socket.
            bool IsConnected () const;
            /// \brief
            /// Async connect to a host with the given address.
            /// \param[in] address Address of host to connect to.
            void Connect (const Address &address);
        #if defined (TOOLCHAIN_OS_Windows)
            /// \brief
            /// Disconnect from peer.
            /// \param[in] reuseSocket If true, the socket will be made available for Connect.
            void Disconnect (bool reuseSocket);
        #endif // defined (TOOLCHAIN_OS_Windows)

            /// \brief
            /// Return true if socket is in listening mode.
            /// \return true if socket is in listening mode.
            bool IsListening () const;
            /// \brief
            /// Listen for incoming connections.
            /// \param[in] maxPendingConnections Maximum number of waiting connections.
            void Listen (util::i32 maxPendingConnections = DEFAULT_MAX_PENDING_CONNECTIONS);
            /// \brief
            /// Start async connections wait.
            void Accept ();

            /// \brief
            /// Return true if SO_KEEPALIVE option is set.
            /// \return true = SO_KEEPALIVE set, false = SO_KEEPALIVE not set.
            bool IsKeepAlive () const;
            /// \brief
            /// Set or clear the SO_KEEPALIVE option and optionally specify it's parameters.
            /// \param[in] keepAlive true = set SO_KEEPALIVE, false = clear SO_KEEPALIVE.
            /// \param[in] idleTime How long to idle before sending keepalive probes (in seconds).
            /// \param[in] interval How long to wait between each probe (in seconds).
            /// \param[in] count How many probes to send before disconnecting.
            void SetKeepAlive (
                bool keepAlive,
                util::ui32 idleTime = util::UI32_MAX,
                util::ui32 interval = util::UI32_MAX,
                util::ui32 count = util::UI32_MAX);

            /// \brief
            /// Check if the socket Nagle option is set.
            /// \return true = Nagle option is set.
            bool IsNagle () const;
            /// \brief
            /// Set the socket Nagle option.
            /// \param[in] nagle true = set, false = unset.
            void SetNagle (bool nagle);

            /// \struct Socket::Linger Socket.h thekogans/stream/Socket.h
            ///
            /// \brief
            /// Holds the information about the socket linger state.
            struct _LIB_THEKOGANS_STREAM_DECL Linger {
                /// \brief
                /// true == linger, false = don't linger.
                bool on;
                /// \brief
                /// If on == true, how long to linger.
                util::ui32 seconds;
                /// \brief
                /// ctor.
                /// \param[in] on_ true == linger, false = don't linger.
                /// \param[in] seconds_ If on == true, how long to linger.
                Linger (
                    bool on_ = false,
                    util::ui32 seconds_ = 0) :
                    on (on_),
                    seconds (seconds_) {}
            };
            /// \brief
            /// Return socket current linger state.
            /// \return Socket current linger state.
            Linger GetLinger () const;
            /// \brief
            /// Set socket new linger state.
            /// \param[in] linger Socket new linger state.
            void SetLinger (const Linger &linger);

            /// \brief
            /// Shutdown type.
            enum ShutdownType {
                /// \brief
                /// Shutdown the read end.
                ShutdownRead,
                /// \brief
                /// Shutdown the write end.
                ShutdownWrite,
                /// \brief
                /// Shutdown both the read and the write ends.
                ShutdownBoth
            };

            /// \brief
            /// Shutdown either the read, write or both ends of the
            /// socket without closing it.
            /// \param[in] shutdownType One of ShutdownRead,
            /// ShutdownWrite or ShutdownBoth.
            void Shutdown (ShutdownType shutdownType = ShutdownBoth);

        protected:
            // Stream
            /// \brief
            /// Used by \see{AsyncIoEventQueue::WaitForEvents} to notify the
            /// stream that an overlapped operation has completed successfully.
            /// \param[in] overlapped Overlapped that completed successfully.
            virtual void HandleOverlapped (Overlapped &overlapped) throw () override;
        };

    } // namespace stream
} // namespace thekogans

#endif // !defined (__thekogans_stream_TCPSocket_h)
