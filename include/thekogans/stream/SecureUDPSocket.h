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

#if !defined (__thekogans_stream_SecureUDPSocket_h)
#define __thekogans_stream_SecureUDPSocket_h

#if defined (THEKOGANS_STREAM_HAVE_OPENSSL)

#include <memory>
#include <list>
#include "thekogans/util/Environment.h"
#include "thekogans/util/Buffer.h"
#include "thekogans/util/SpinLock.h"
#include "thekogans/stream/Config.h"
#include "thekogans/stream/UDPSocket.h"
#include "thekogans/stream/OpenSSLUtils.h"

namespace thekogans {
    namespace stream {

        /// \brief
        /// Forward declaration of \see{ServerSecureUDPSocket}.
        struct ServerSecureUDPSocket;

            /// \brief
            /// Called when a client \see{SecureUDPSocket} has established a
            /// connection to the server.
            /// \param[in] secureUDPSocket \see{SecureUDPSocket} that established
            /// a connection.
            /// NOTE: The DTLS handshake has not occurred yet. Call
            /// \see{SecureUDPSocket::SessionConnect} to begin a DTLS handshake.
            virtual void HandleSecureUDPSocketConnected (
                SecureUDPSocket &udpSocket) throw ();
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
        /// \struct SecureUDPSocket SecureUDPSocket.h thekogans/stream/SecureUDPSocket.h
        ///
        /// \brief
        /// SecureUDPSocket builds on UDPSocket to add DTLS to the connection.
        /// SecureUDPSocket has two modes of operation. 1) thekogans preferred.
        /// This mode tries to use the best practices (as of 2015) to provide
        /// a simple file driven DTLS configuration. \see{ClientSecureUDPSocket}
        /// and \see{ServerSecureUDPSocket} to see how Context is used to
        /// configure both client and server sides of a secure connection. In
        /// this mode of operation, you don't instantiate a SecureUDPSocket
        /// directly but, in fact, use either \see{ClientSecureUDPSocket::Context}
        /// or \see{ServerSecureUDPSocket::Context}. 2) Direct SecureUDPSocket
        /// usage mode. If your needs tend to the exotic (callbacks?), use
        /// SecureUDPSocket directly. SessionConnect (client) and SessionAccept
        /// (server) take a SSL_CTX that you can fill with whatever values that
        /// make sense for your app.

        struct _LIB_THEKOGANS_STREAM_DECL SecureUDPSocket : public UDPSocket {
            /// \brief
            /// Declare \see{RefCounted} pointers.
            THEKOGANS_UTIL_DECLARE_REF_COUNTED_POINTERS (SecureUDPSocket)

            /// \brief
            /// SecureUDPSocket has a private heap to help with memory
            /// management, performance, and global heap fragmentation.
            THEKOGANS_UTIL_DECLARE_HEAP_WITH_LOCK (SecureUDPSocket, util::SpinLock)

        protected:
            /// \brief
            /// Active DTLS session state.
            SSLPtr ssl;
            /// \brief
            /// Active DTLS extended session info.
            SessionInfo sessionInfo;
            /// \brief
            /// We need a bunch of notifications to do our job.
            /// Chain the old callback in case it was specified in SSL_CTX.
            void (*oldInfoCallback) (
                const SSL *ssl,
                int type,
                int val);
            // Async info.
            /// \brief
            /// Input side of the async connection.
            crypto::BIOPtr inBIO;
            /// \brief
            /// Output side of the async connection.
            crypto::BIOPtr outBIO;
            /// \brief
            /// Convenient typedef for std::list<util::Buffer>.
            typedef std::list<util::Buffer> Buffers;
            /// \brief
            /// List of buffers waiting to be encrypted
            /// before being put on the wire.
            Buffers encryptList;
            /// \brief
            /// List of buffers that have arrived from
            /// the wire, and are waiting to be decrypted
            /// before being delivered to an \see{AsyncIoEventSink}.
            Buffers decryptList;
            /// \brief
            /// RunDTLS, encryptList and decryptList are shared
            /// resources that need to be protected.
            util::SpinLock spinLock;
            /// \brief
            /// RunDTLS is not re-entrant. It grabs this lock
            /// on entrance, and releases it on exit.
            util::SpinLock inRunDTLS;

        public:
            /// \brief
            /// ctor.
            /// Wrap an OS handle.
            /// \param[in] handle Socket handle of incoming connection.
            SecureUDPSocket (THEKOGANS_UTIL_HANDLE handle = THEKOGANS_UTIL_INVALID_HANDLE_VALUE) :
                UDPSocket (handle),
                oldInfoCallback (0) {}
            /// \brief
            /// ctor.
            /// \param[in] family Address family specification.
            /// \param[in] type Socket type specification.
            /// \param[in] protocol Socket protocol specification.
            SecureUDPSocket (
                int family,
                int type,
                int protocol) :
                UDPSocket (family, type, protocol),
                oldInfoCallback (0) {}

            // Stream
            /// \brief
            /// Read bytes from the stream.
            /// \param[out] buffer Where to place the bytes.
            /// \param[in] count Buffer length.
            /// \return Count of bytes actually placed in the buffer.
            virtual std::size_t Read (
                void *buffer,
                std::size_t count);
            /// \brief
            /// Write bytes to the stream.
            /// \param[in] buffer Bytes to write.
            /// \param[in] count Buffer length.
            /// \return Count of bytes actually written.
            virtual std::size_t Write (
                const void *buffer,
                std::size_t count);

            /// \brief
            /// Async write a buffer to the stream.
            /// \param[in] buffer Buffer to write.
            virtual void WriteBuffer (util::Buffer buffer);

            // SecureUDPSocket
            /// \brief
            /// Initiate a client side DTLS handshake.
            /// NOTE: This function can be used in either sync or async modes.
            /// If the socket is sync and the function doesn't throw, the handshake
            /// succeeded. If the socket is async, the handshake completion will be
            /// reported through \see{AsyncIoEventSink::HandleSecureUDPSocketHandshakeCompleted}.
            /// \param[in] ctx SSL_CTX from which to create the SSL object.
            /// \param[in] sessionInfo_ Extended session info.
            void SessionConnect (
                SSL_CTX *ctx,
                const SessionInfo &sessionInfo_);
            /// \brief
            /// Initiate a server side DTLS handshake.
            /// NOTE: This function can be used in either sync or async modes.
            /// If the socket is sync and the function doesn't throw, the handshake
            /// succeeded. If the socket is async, the handshake completion will be
            /// reported through \see{AsyncIoEventSink::HandleSecureUDPSocketHandshakeCompleted}.
            /// \param[in] ctx SSL_CTX from which to create the SSL object.
            /// \param[in] sessionInfo_ Extended session info.
            void SessionAccept (
                SSL_CTX *ctx,
                const SessionInfo &sessionInfo_);
            /// \brief
            /// Return true if session was reused.
            /// \return true if session was reused.
            bool IsSessionReused () const;
            /// \brief
            /// Return true if the number of bytes transfered exceeds
            /// some application defined renegotiationFrequency.
            /// \return true = Call RenegotiateSession at some convenient
            /// application protocol point.
            inline bool ShouldRenegotiate () const {
                return sessionInfo.countTransfered > sessionInfo.renegotiationFrequency;
            }
            /// \brief
            /// Forces a re-handshake. Use this function when you have
            /// determined that the shared secret has seen enough use,
            /// and should be renegotiated. To that end SecureUDPSocket
            /// maintains the count of bytes transfered. Use ShouldRenegotiate
            /// to determine if that's greater than some application
            /// defined renegotiationFrequency, and if so, call this
            /// function at a convenient place in your protocol.
            /// NOTE: This function can be used in either sync or async modes.
            /// If the socket is sync and the function doesn't throw, the handshake
            /// succeeded. If the socket is async, the handshake completion will be
            /// reported through \see{AsyncIoEventSink::HandleSecureUDPSocketHandshakeCompleted}.
            void RenegotiateSession ();
            /// \brief
            /// Return true if proper session shutdown has occurred.
            /// NOTE: 'Proper' is determined by \see{SessionInfo::bidirectionalShutdown}.
            /// \return true if proper session shutdown has occurred.
            bool ShutdownCompleted () const;
            /// \brief
            /// Call this method to do a proper DTLS shutdown.
            /// NOTE: Per DTLS spec, a Shutdown alert must be
            /// send to the server if the session is to be resumable.
            void ShutdownSession ();
            /// \brief
            /// Return SSL *.
            /// \return SSL *.
            inline SSL *GetSSL () const {
                return ssl.get ();
            }
            /// \brief
            /// Return Currently negotiated session. Pass it
            /// back to SecureUDPSocket ctor to attempt session resumption.
            /// NOTE: In order for session resumption to have a
            /// snowballs chance in hell, the server should have been
            /// set up with cachedSessionTTL > 0.
            /// \return Currently negotiated session.
            inline const SessionInfo &GetSessionInfo () const {
                return sessionInfo;
            }

        protected:
            // UDPSocket
            /// \brief
            /// SecureUDPSocket must be connected to a peer by
            /// calling \see{UDPSocket::Connect}. After that use
            /// \see{Read}.
            virtual std::size_t ReadFrom (
                    void * /*buffer*/,
                    std::size_t /*count*/,
                    Address & /*address*/) {
                assert (0);
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "%s", "SecureUDPSocket can't ReadFrom.");
                return -1;
            }
            /// \brief
            /// SecureUDPSocket must be connected to a peer by
            /// calling \see{UDPSocket::Connect}. After that use
            /// \see{Write}.
            virtual std::size_t WriteTo (
                    const void * /*buffer*/,
                    std::size_t /*count*/,
                    const Address & /*address*/) {
                assert (0);
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "%s", "SecureUDPSocket can't WriteTo.");
                return -1;
            }
            /// \brief
            /// SecureUDPSocket must be connected to a peer by
            /// calling \see{UDPSocket::Connect}. After that use
            /// \see{WriteBuffer}.
            virtual void WriteBufferTo (
                    util::Buffer /*buffer*/,
                    const Address & /*address*/) {
                assert (0);
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "%s", "SecureUDPSocket can't WriteBufferTo.");
            }

            /// \brief
            /// Used by the AsyncIoEventQueue to allow the stream to
            /// initialize itself. When this function is called, the
            /// stream is already async, and Stream::AsyncInfo has
            /// been created. At this point the stream should do
            /// whatever stream specific initialization it needs to
            /// do.
            virtual void InitAsyncIo ();
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
            /// In order to be able to report handshake as well as shutdown
            /// completions, we hook the protocol info callback.
            /// \param[in] ssl SSL object that's reporting the event.
            /// \param[in] where Event being reported.
            /// \param[in] ret Result code associated with the event.
            static void InfoCallback (const SSL *ssl, int where, int ret);
            /// \brief
            /// Performs bookkeeping chores after a completed handshake.
            void FinalizeConnection ();
            /// \brief
            /// Performs bookkeeping chores after receipt of a shutdown alert.
            void ShutdownConnection ();
            /// \brief
            /// Return the type of work \see{RunDTLS} should perform.
            /// \param[out] decryptBuffer If there's decryption to be
            /// performed, decryptBuffer will hold the pointer to the
            /// buffer.
            /// \param[out] encryptBuffer If there's encryption to be
            /// performed, encryptBuffer will hold the pointer to the
            /// buffer.
            /// \return true = there's work to do, false = no work to do.
            bool GetWorkToDo (
                util::Buffer *&decryptBuffer,
                util::Buffer *&encryptBuffer);
            /// \brief
            /// Async DTLS pump. Runs the following state machine:
            /// - !decryptList.empty (), call BIO_write (inBIO, decryptList.front ()).
            /// - drain the SSL object of all available records by calling SSL_read.
            /// - !encryptList.empty (), call SSL_write (..., encryptList.front ()).
            /// - BIO_ctrl_pending (outBIO), drain the outBIO, and put the cipher text on the wire.
            void RunDTLS ();
            /// \brief
            /// Return true if a fatal error occurred. OpenSSL reports
            /// non fatal errors (SSL_ERROR_WANT_READ/WRITE) when it
            /// can't make progress and has to wait for more io.
            /// \return true = fatal error occurred.
            bool IsFatalError (int result) const;

            friend ServerSecureUDPSocket;

            /// \brief
            /// Streams are neither copy constructable, nor assignable.
            THEKOGANS_STREAM_DISALLOW_COPY_AND_ASSIGN (SecureUDPSocket)
        };

    } // namespace stream
} // namespace thekogans

#endif // defined (THEKOGANS_STREAM_HAVE_OPENSSL)

#endif // !defined (__thekogans_stream_SecureUDPSocket_h)
