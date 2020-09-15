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

#if !defined (__thekogans_stream_AsyncIoEventSink_h)
#define __thekogans_stream_AsyncIoEventSink_h

#include <memory>
#include "thekogans/util/Types.h"
#include "thekogans/util/RefCounted.h"
#include "thekogans/util/Buffer.h"
#include "thekogans/util/Exception.h"
#include "thekogans/stream/Config.h"
#include "thekogans/stream/Address.h"
#include "thekogans/stream/TCPSocket.h"
#include "thekogans/stream/ServerUDPSocket.h"
#if defined (THEKOGANS_STREAM_HAVE_OPENSSL)
    #include "thekogans/stream/SecureTCPSocket.h"
    #include "thekogans/stream/SecureUDPSocket.h"
#endif // defined (THEKOGANS_STREAM_HAVE_OPENSSL)

namespace thekogans {
    namespace stream {

    #if defined (TOOLCHAIN_OS_Windows)
        struct ServerNamedPipe;
    #endif // defined (TOOLCHAIN_OS_Windows)
        struct ServerTCPSocket;
    #if defined (THEKOGANS_STREAM_HAVE_OPENSSL)
        struct ServerSecureTCPSocket;
        struct ServerSecureUDPSocket;
    #endif // defined (THEKOGANS_STREAM_HAVE_OPENSSL)

        /// \struct AsyncIoEventSink AsyncIoEventSink.h thekogans/stream/AsyncIoEventSink.h
        ///
        /// \brief
        /// AsyncIoEventSink represents the callback mechanism by which async io events
        /// are delivered. AsyncIoEventSinks can be chained together to provide a filtering
        /// pipeline.
        ///
        /// IMPORTANT NOTE: This api is called asynchronously, and because of that, there
        /// are some restrictions on what is considered in good taste. The following are
        /// very much encouraged:
        /// - Do be quick about it:
        ///   - Queue a job on a \see{thekogans::util::JobQueue}!
        ///   - Schedule a job on a \see{thekogans::util::Scheduler}!
        ///   - Prime a \see{thekogans::util::Pipeline} stage!
        ///   - Borrow a \see{thekogans::util::JobQueue} from a
        ///     \see{thekogans::util::JobQueuePool}!
        /// - About the only sensible thing to do when responding
        ///   to \see{AsyncIoEventSink::HandleStreamError} and
        ///   \see{AsyncIoEventSink::HandleStreamDisconnect} is to call
        ///   \see{AsyncIoEventQueue::DeleteStream} to aggregate it for
        ///   deletion (after \see{AsyncIoEventQueue::WaitForEvents}
        ///   returns). Please consult any one of the \see{TCPSocket}
        ///   based examples provided with thekogans_stream to see the
        ///   right way to do this. The one exception to this rule is
        ///   when processing THEKOGANS_UTIL_OS_ERROR_CODE_TIMEOUT. In
        ///   some situations it's appropriate to escalate the timeout
        ///   a few times before giving up.
        /// - Honor the throw ()!
        ///   This last one cannot be over stressed. Again, you are being
        ///   called asynchronously from a completely different thread.
        ///   There is no one there to catch your exceptions. YOU WILL SEG FAULT!

        struct _LIB_THEKOGANS_STREAM_DECL AsyncIoEventSink :
                public virtual util::ThreadSafeRefCounted {
            /// \brief
            /// Convenient typedef for util::ThreadSafeRefCounted::Ptr<AsyncIoEventSink>.
            typedef util::ThreadSafeRefCounted::Ptr<AsyncIoEventSink> Ptr;

        protected:
            /// \brief
            /// Next AsyncIoEventSink in the chain.
            AsyncIoEventSink::Ptr next;

        public:
            /// \brief
            /// dtor.
            /// \param[in] next_ Next AsyncIoEventSink in the chain.
            AsyncIoEventSink (AsyncIoEventSink::Ptr next_ = 0) :
                next (next_) {}
            /// \brief
            /// dtor.
            virtual ~AsyncIoEventSink () {}

            /// \brief
            /// Chain unimplemented callbacks to the given handler.
            /// \param[in] next_ Handler to be called for all unimplemented callbacks.
            inline void SetNext (AsyncIoEventSink &next_) {
                next.Reset (&next_);
            }

            /// \brief
            /// Called to initiate stream error processing.
            /// \param[in] stream \see{Stream} on which an error occurred.
            /// \param[in] exception \see{util::Exception} representing the error.
            virtual void HandleStreamError (
                Stream &stream,
                const util::Exception &exception) throw ();

            /// \brief
            /// Called when a remote peer has disconnected.
            /// \param[in] stream \see{Stream} which has been disconnected.
            virtual void HandleStreamDisconnect (Stream &stream) throw ();

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
                    Stream &stream,
                    util::Endianness endianness,
                    std::size_t count) throw () {
                return util::Buffer (endianness, count);
            }
            /// \brief
            /// Called when new data has arrived on a stream.
            /// \param[in] stream \see{Stream} that received the data.
            /// \param[in] buffer The new data.
            virtual void HandleStreamRead (
                Stream &stream,
                util::Buffer buffer) throw ();

            /// \brief
            /// The analog to the GetBuffer above. Used by Write handler
            /// to allow the sink to add appropriate protocol headers.
            /// \param[in] stream \see{Stream} that will receive the buffer.
            /// \param[in] buffer \see{Stream::Write} bufffer.
            /// \param[in] count \see{Stream::Write} buffer length.
            /// \return \see{util::Buffer} to write to the stream.
            virtual util::Buffer GetBuffer (
                    Stream &stream,
                    util::Endianness endianness,
                    const void *buffer,
                    std::size_t count) throw () {
                return util::Buffer (
                    endianness,
                    (const util::ui8 *)buffer,
                    (const util::ui8 *)buffer + count);
            }
            /// \brief
            /// Called when data was written to a stream.
            /// \param[in] stream Stream where data was written.
            /// \param[in] buffer The written data.
            virtual void HandleStreamWrite (
                Stream &stream,
                util::Buffer buffer) throw ();

        #if defined (TOOLCHAIN_OS_Windows)
            /// \brief
            /// Called to report a connection on a \see{ServerNamedPipe}.
            /// \param[in] serverNamedPipe \see{ServerNamedPipe} on which
            /// the connection occurred.
            virtual void HandleServerNamedPipeConnection (
                ServerNamedPipe &serverNamedPipe) throw ();
        #endif // defined (TOOLCHAIN_OS_Windows)

            /// \brief
            /// Called when a client \see{TCPSocket} has established
            /// a connection to the server.
            /// \param[in] tcpSocket \see{TCPSocket} that established
            /// a connection.
            virtual void HandleTCPSocketConnected (TCPSocket &tcpSocket) throw ();
        #if defined (THEKOGANS_STREAM_HAVE_OPENSSL)
            /// \brief
            /// Called when a client \see{SecureTCPSocket} has established a
            /// connection to the server.
            /// \param[in] secureTCPSocket \see{SecureTCPSocket} that established
            /// a connection.
            /// NOTE: The TLS handshake has not occurred yet. Call
            /// \see{SecureTCPSocket::SessionConnect} to begin a TLS handshake.
            virtual void HandleSecureTCPSocketConnected (
                SecureTCPSocket &tcpSocket) throw ();
            /// \brief
            /// Called when a client \see{SecureUDPSocket} has established a
            /// connection to the server.
            /// \param[in] secureUDPSocket \see{SecureUDPSocket} that established
            /// a connection.
            /// NOTE: The DTLS handshake has not occurred yet. Call
            /// \see{SecureUDPSocket::SessionConnect} to begin a DTLS handshake.
            virtual void HandleSecureUDPSocketConnected (
                SecureUDPSocket &udpSocket) throw ();
        #endif // defined (THEKOGANS_STREAM_HAVE_OPENSSL)

            /// \brief
            /// Override this method if you're deriving from a TCPSocket.
            /// \param[in] handle OS socket handle to wrap.
            /// \return A \see{TCPSocket} derivative.
            virtual TCPSocket::Ptr GetTCPSocket (THEKOGANS_UTIL_HANDLE handle) throw () {
                return TCPSocket::Ptr (new TCPSocket (handle));
            }
            /// \brief
            /// Called to report that the given \see{TCPSocket} has been shutdown.
            /// \param[in] tcpSocket \see{TCPSocket} that was shutdown.
            /// \param[in] shutdownType One of \see{TCPSocket::ShutdownType}.
            virtual void HandleTCPSocketShutdown (
                TCPSocket &tcpSocket,
                TCPSocket::ShutdownType shutdownType) throw ();
            /// \brief
            /// Called to report a new connection on a \see{ServerTCPSocket}.
            /// \param[in] serverTCPSocket \see{ServerTCPSocket} on which the
            /// new connection occurred.
            /// \param[in] connection The new connection socket.
            /// NOTE: The new connection will be sync (blocking).
            virtual void HandleServerTCPSocketConnection (
                ServerTCPSocket &serverTCPSocket,
                TCPSocket::Ptr connection) throw ();
            /// \brief
            /// Called to report a new connection on a \see{ServerUDPSocket}.
            /// \param[in] serverUDPSocket \see{ServerUDPSocket} on which the
            /// new connection occurred.
            /// \param[in] connection The new connection info.
            /// NOTE: The new connection will be sync (blocking).
            virtual void HandleServerUDPSocketConnection (
                ServerUDPSocket &serverUDPSocket,
                ServerUDPSocket::Connection::Ptr connection) throw ();

        #if defined (THEKOGANS_STREAM_HAVE_OPENSSL)
            /// \brief
            /// Override this method if you're deriving from a \see{SecureTCPSocket}.
            /// \param[in] handle OS socket handle to wrap.
            /// \return A SecureTCPSocket derivative.
            virtual SecureTCPSocket::Ptr GetSecureTCPSocket (THEKOGANS_UTIL_HANDLE handle) throw () {
                return SecureTCPSocket::Ptr (new SecureTCPSocket (handle));
            }
            /// \brief
            /// Called to report a new connection on a \see{ServerSecureTCPSocket}.
            /// \param[in] serverSecureTCPSocket \see{ServerSecureTCPSocket} on which
            /// the new connection occurred.
            /// \param[in] connection The new connection socket.
            /// NOTE: The new connection will be sync (blocking).
            /// NOTE: The TLS handshake has not occurred yet. After
            /// adding the new connection to the \see{AsyncIoEventQueue},
            /// call \see{SecureTCPSocket::SessionAccept} to begin a TLS
            /// handshake.
            virtual void HandleServerSecureTCPSocketConnection (
                ServerSecureTCPSocket &serverSecureTCPSocket,
                SecureTCPSocket::Ptr connection) throw ();
            /// \brief
            /// Called to report a new connection on a \see{ServerSecureUDPSocket}.
            /// \param[in] serverSecureUDPSocket \see{ServerSecureUDPSocket} on which
            /// the new connection occurred.
            /// \param[in] connection The new connection socket.
            /// NOTE: The new connection will be sync (blocking).
            /// NOTE: The DTLS handshake has not occurred yet. After
            /// adding the new connection to the \see{AsyncIoEventQueue},
            /// call \see{SecureUDPSocket::SessionAccept} to begin
            /// a DTLS handshake.
            virtual void HandleServerSecureUDPSocketConnection (
                ServerSecureUDPSocket &serverSecureUDPSocket,
                SecureUDPSocket::Ptr connection) throw ();

            /// \brief
            /// Called when the TLS handshake is about to start.
            /// This could be client side SSL_connect, server side
            /// SSL_accept or client/server side renegotiation.
            /// \param[in] secureTCPSocket \see{SecureTCPSocket}
            /// on which the TLS handshake is about to start.
            virtual void HandleSecureTCPSocketHandshakeStarting (
                SecureTCPSocket &secureTCPSocket) throw ();
            /// \brief
            /// Called when the TLS handshake completed. This could
            /// be client side SSL_connect, server side SSL_accept
            /// or client/server side renegotiation.
            /// \param[in] secureTCPSocket \see{SecureTCPSocket}
            /// on which the TLS handshake completed.
            virtual void HandleSecureTCPSocketHandshakeCompleted (
                SecureTCPSocket &secureTCPSocket) throw ();
            /// \brief
            /// Called when a bidirectional TLS shutdown completed.
            /// \param[in] secureTCPSocket \see{SecureTCPSocket}
            /// on which the TLS shutdown completed.
            virtual void HandleSecureTCPSocketShutdownCompleted (
                SecureTCPSocket &secureTCPSocket) throw ();

            /// \brief
            /// Called when the DTLS handshake is about to start.
            /// This could be client side SSL_connect, server side
            /// SSL_accept or client/server side renegotiation.
            /// \param[in] secureUDPSocket \see{SecureUDPSocket} on
            /// which the DTLS handshake completed.
            virtual void HandleSecureUDPSocketHandshakeStarting (
                SecureUDPSocket &secureUDPSocket) throw ();
            /// \brief
            /// Called when the DTLS handshake completed. This could
            /// be client side SSL_connect, server side SSL_accept
            /// or client/server side renegotiation.
            /// \param[in] secureUDPSocket \see{SecureUDPSocket} on
            /// which the DTLS handshake completed.
            virtual void HandleSecureUDPSocketHandshakeCompleted (
                SecureUDPSocket &secureUDPSocket) throw ();
            /// \brief
            /// Called when a bidirectional DTLS shutdown completed.
            /// \param[in] secureUDPSocket \see{SecureUDPSocket} on
            /// which the DTLS shutdown completed.
            virtual void HandleSecureUDPSocketShutdownCompleted (
                SecureUDPSocket &secureUDPSocket) throw ();
        #endif // defined (THEKOGANS_STREAM_HAVE_OPENSSL)

            /// \brief
            /// Called when a new datagram has arrived on a (Secure)UDPSocket.
            /// \param[in] udpSocket (Secure)UDPSocket that received the datagram.
            /// \param[in] buffer The new datagram.
            /// \param[in] address Peer address that sent the datagram.
            virtual void HandleUDPSocketReadFrom (
                UDPSocket &udpSocket,
                util::Buffer buffer,
                const Address &address) throw ();
            /// \brief
            /// Called when a datagram was written to a (Secure)UDPSocket.
            /// \param[in] udpSocket (Secure)UDPSocket where the datagram was written.
            /// \param[in] buffer The written datagram.
            /// \param[in] address Peer address that received the datagram.
            virtual void HandleUDPSocketWriteTo (
                UDPSocket &udpSocket,
                util::Buffer buffer,
                const Address &address) throw ();

            /// \brief
            /// Called when a new datagram has arrived on a (Secure)UDPSocket.
            /// \param[in] udpSocket (Secure)UDPSocket that received the datagram.
            /// \param[in] buffer The new datagram.
            /// \param[in] from Peer address that sent the datagram.
            /// \param[in] to Local address that received the datagram.
            virtual void HandleUDPSocketReadMsg (
                UDPSocket &udpSocket,
                util::Buffer buffer,
                const Address &from,
                const Address &to) throw ();
            /// \brief
            /// Called when a datagram was written to a (Secure)UDPSocket.
            /// \param[in] udpSocket (Secure)UDPSocket where the datagram was written.
            /// \param[in] buffer The written datagram.
            /// \param[in] from Local address from which the datagram was sent.
            /// \param[in] to Peer address that will receive the datagram.
            virtual void HandleUDPSocketWriteMsg (
                UDPSocket &udpSocket,
                util::Buffer buffer,
                const Address &from,
                const Address &to) throw ();
        };

    } // namespace stream
} // namespace thekogans

#endif // !defined (__thekogans_stream_AsyncIoEventSink_h)
