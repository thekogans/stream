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

#if !defined (__thekogans_stream_SecureTCPSocket_h)
#define __thekogans_stream_SecureTCPSocket_h

#if defined (THEKOGANS_STREAM_HAVE_OPENSSL)

#include <memory>
#include <list>
#include "thekogans/util/SpinLock.h"
#include "thekogans/util/Buffer.h"
#include "thekogans/stream/Config.h"
#include "thekogans/stream/TCPSocket.h"
#include "thekogans/stream/OpenSSLUtils.h"

namespace thekogans {
    namespace stream {

        /// \struct SecureTCPSocket SecureTCPSocket.h thekogans/stream/SecureTCPSocket.h
        ///
        /// \brief
        /// SecureTCPSocket builds on \see{TCPSocket} to add TLS to the connection.
        /// SecureTCPSocket has two modes of operation. 1) thekogans preferred.
        /// This mode tries to use the best practices (as of 2015) to provide
        /// a simple file driven TLS configuration. \see{ClientSecureTCPSocket}
        /// and \see{ServerSecureTCPSocket} to see how Context is used to
        /// configure both client and server sides of a secure connection. In
        /// this mode of operation, you don't instantiate a SecureTCPSocket
        /// directly but, in fact, use either \see{ClientSecureTCPSocket::Context}
        /// or \see{ServerSecureTCPSocket::Context}. examples/securetcpecho provides
        /// a good example of this usage mode. 2) Direct SecureTCPSocket
        /// usage mode. If your needs tend to the exotic (callbacks?), use
        /// SecureTCPSocket directly. SessionConnect (client) and SessionAccept
        /// (server) take a SSL_CTX that you can fill with whatever values that
        /// make sense for your app.

        struct _LIB_THEKOGANS_STREAM_DECL SecureTCPSocket : public TCPSocket {
            /// \brief
            /// Convenient typedef for util::ThreadSafeRefCounted::Ptr<SecureTCPSocket>.
            typedef util::ThreadSafeRefCounted::Ptr<SecureTCPSocket> Ptr;

            /// \brief
            /// SecureTCPSocket has a private heap to help with memory
            /// management, performance, and global heap fragmentation.
            THEKOGANS_UTIL_DECLARE_HEAP_WITH_LOCK (SecureTCPSocket, util::SpinLock)

        protected:
            /// \brief
            /// Active TLS session state.
            SSLPtr ssl;
            /// \brief
            /// Active TLS extended session info.
            SessionInfo sessionInfo;
            /// \brief
            /// We need a bunch of notifications to do our job.
            /// Chain the old callback in case it was specified in SSL_CTX.
            void (*oldInfoCallback) (
                const SSL *ssl,
                int type,
                int val);
            /// \struct SecureTCPSocket::AsyncInfoEx SecureTCPSocket.h thekogans/stream/SecureTCPSocket.h
            ///
            /// \brief
            /// Encapsulates extended async info.
            struct _LIB_THEKOGANS_STREAM_DECL AsyncInfoEx {
                /// \struct SecureTCPSocket::AsyncInfoEx::Deleter SecureTCPSocket.h thekogans/stream/SecureTCPSocket.h
                ///
                /// \brief
                /// Custom deleter for AsyncInfoEx. This class is
                /// necessary to shutup msvc.
                struct Deleter {
                    /// \brief
                    /// Called by unique_ptr::~unique_ptr.
                    /// \param[in] asyncInfo AsyncInfoEx to delete.
                    void operator () (AsyncInfoEx *asyncInfoEx) {
                        delete asyncInfoEx;
                    }
                };
                /// \brief
                /// Convenient typedef for std::unique_ptr<AsyncInfoEx> UniquePtr.
                typedef std::unique_ptr<AsyncInfoEx, Deleter> UniquePtr;

                /// \brief
                /// AsyncInfoEx has a private heap to help with memory
                /// management, performance, and global heap fragmentation.
                THEKOGANS_UTIL_DECLARE_HEAP_WITH_LOCK (AsyncInfoEx, util::SpinLock)

                /// \brief
                /// Used in RunTLS.
                SecureTCPSocket &secureTCPSocket;
                /// \brief
                /// Input side of the async connection.
                crypto::BIOPtr inBIO;
                /// \brief
                /// Output side of the async connection.
                crypto::BIOPtr outBIO;
                /// \brief
                /// List of buffers waiting to be encrypted
                /// before being put on the wire.
                std::list<util::Buffer::UniquePtr> encryptList;
                /// \brief
                /// List of buffers that have arrived from
                /// the wire, and are waiting to be decrypted
                /// before being delivered to an \see{AsyncIoEventSink}.
                std::list<util::Buffer::UniquePtr> decryptList;
                /// \brief
                /// Protects access to encryptList and decryptList.
                util::SpinLock spinLock;
                /// \brief
                /// RunTLS is not re-entrant. It grabs this lock
                /// on entrance, and releases it on exit. This way
                /// async callbacks can call in to a SecureTCPSocket
                /// without worrying about deadlock.
                util::SpinLock inRunTLS;

                /// \brief
                /// ctor.
                /// \param[in] secureTCPSocket_ Used in RunTLS.
                explicit AsyncInfoEx (SecureTCPSocket &secureTCPSocket_);

                /// \brief
                /// Hook the SecureTCPSocket::ssl bio.
                void HookSSL ();

                /// \brief
                /// Add a buffer to the encryptList and call RunTLS.
                /// \param[in] buffer Buffer to add to the encryptList.
                void AddEncryptBuffer (util::Buffer::UniquePtr buffer);
                /// \brief
                /// Add a buffer to the decryptList and call RunTLS.
                /// \param[in] buffer Buffer to add to the decryptList.
                void AddDecryptBuffer (util::Buffer::UniquePtr buffer);

                /// \brief
                /// Async TLS pump. Runs the following state machine:
                /// - !decryptList.empty (), call BIO_write (inBIO, decryptList.front ()).
                /// - drain the SSL object of all available records by calling SSL_read.
                /// - !encryptList.empty (), call SSL_write (..., encryptList.front ()).
                /// - BIO_ctrl_pending (outBIO) != 0, drain the outBIO, and put the cipher text on the wire.
                void RunTLS ();

            private:
                /// \brief
                /// Return the type of work \see{RunTLS} should perform.
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
            };
            /// \brief
            /// \see{Stream::AsyncInfo} extensions.
            AsyncInfoEx::UniquePtr asyncInfoEx;

        public:
            /// \brief
            /// ctor.
            /// Wrap an OS handle.
            /// \param[in] handle Socket handle of incoming connection.
            SecureTCPSocket (THEKOGANS_UTIL_HANDLE handle = THEKOGANS_UTIL_INVALID_HANDLE_VALUE) :
                TCPSocket (handle),
                oldInfoCallback (0) {}
            /// \brief
            /// ctor.
            /// \param[in] family Address family specification.
            /// \param[in] type Socket type specification.
            /// \param[in] protocol Socket protocol specification.
            SecureTCPSocket (
                int family,
                int type,
                int protocol) :
                TCPSocket (family, type, protocol),
                oldInfoCallback (0) {}

            // Stream
            /// \brief
            /// Read bytes from the stream.
            /// \param[out] buffer Where to place the bytes.
            /// \param[in] count Buffer length.
            /// \return Count of bytes actually placed in the buffer.
            virtual util::ui32 Read (
                void *buffer,
                util::ui32 count);
            /// \brief
            /// Write bytes to the stream.
            /// \param[in] buffer Bytes to write.
            /// \param[in] count Buffer length.
            /// \return Count of bytes actually written.
            virtual util::ui32 Write (
                const void *buffer,
                util::ui32 count);

            /// \brief
            /// Async write a buffer to the stream.
            /// \param[in] buffer Buffer to write.
            virtual void WriteBuffer (util::Buffer::UniquePtr buffer);

            // SecureTCPSocket
            /// \brief
            /// Initiate a client side TLS handshake.
            /// NOTE: This function can be used in either sync or async modes.
            /// If the socket is sync and the function doesn't throw, the handshake
            /// succeeded. If the socket is async, the handshake completion will be
            /// reported through \see{AsyncIoEventSink::HandleSecureTCPSocketHandshakeCompleted}.
            /// \param[in] ctx SSL_CTX from which to create the SSL object.
            /// \param[in] sessionInfo_ Extended session info.
            void SessionConnect (
                SSL_CTX *ctx,
                const SessionInfo &sessionInfo_);
            /// \brief
            /// Initiate a server side TLS handshake.
            /// NOTE: This function can be used in either sync or async modes.
            /// If the socket is sync and the function doesn't throw, the handshake
            /// succeeded. If the socket is async, the handshake completion will be
            /// reported through \see{AsyncIoEventSink::HandleSecureTCPSocketHandshakeCompleted}.
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
            /// and should be renegotiated. To that end SecureTCPSocket
            /// maintains the count of bytes transfered. Use ShouldRenegotiate
            /// to determine if that's greater than some application
            /// defined renegotiationFrequency, and if so, call this
            /// function at a convenient place in your protocol.
            /// NOTE: This function can be used in either sync or async modes.
            /// If the socket is sync and the function doesn't throw, the handshake
            /// succeeded. If the socket is async, the handshake completion will be
            /// reported through \see{AsyncIoEventSink::HandleSecureTCPSocketHandshakeCompleted}.
            void RenegotiateSession ();
            /// \brief
            /// Return true if proper session shutdown has occurred.
            /// NOTE: 'Proper' is determined by \see{SessionInfo::bidirectionalShutdown}.
            /// \return true if proper session shutdown has occurred.
            bool ShutdownCompleted () const;
            /// \brief
            /// Call this method to do a proper TLS shutdown.
            /// NOTE: Per TLS spec, a Shutdown alert must be
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
            /// back to SecureTCPSocket ctor to attempt session resumption.
            /// NOTE: In order for session resumption to have a
            /// snowballs chance in hell, the server should have been
            /// set up with cachedSessionTTL > 0.
            /// \return Currently negotiated session.
            inline const SessionInfo &GetSessionInfo () const {
                return sessionInfo;
            }

        protected:
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
            static void InfoCallback (
                const SSL *ssl,
                int where,
                int ret);
            /// \brief
            /// Performs bookkeeping chores after a completed handshake.
            void FinalizeConnection ();
            /// \brief
            /// Performs bookkeeping chores after receipt of a shutdown alert.
            void ShutdownConnection ();
            /// \brief
            /// Return true if a fatal error occurred. OpenSSL reports
            /// non fatal errors (SSL_ERROR_WANT_READ/WRITE) when it
            /// can't make progress and has to wait for more io.
            /// \return true = fatal error occurred.
            bool IsFatalError (int result) const;

            /// \brief
            /// Streams are neither copy constructable, nor assignable.
            THEKOGANS_STREAM_DISALLOW_COPY_AND_ASSIGN (SecureTCPSocket)
        };

    } // namespace stream
} // namespace thekogans

#endif // defined (THEKOGANS_STREAM_HAVE_OPENSSL)

#endif // !defined (__thekogans_stream_SecureTCPSocket_h)
