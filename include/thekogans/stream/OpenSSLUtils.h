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

#if !defined (__thekogans_stream_OpenSSLUtils_h)
#define __thekogans_stream_OpenSSLUtils_h

#if defined (THEKOGANS_STREAM_HAVE_OPENSSL)

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
    #include <winsock2.h>
#endif // defined (TOOLCHAIN_OS_Windows)
#include <memory>
#include <string>
#include <list>
#include <openssl/ssl.h>
#include <openssl/pem.h>
#include "pugixml/pugixml.hpp"
#include "thekogans/util/Types.h"
#include "thekogans/util/RefCounted.h"
#include "thekogans/util/Heap.h"
#include "thekogans/util/SpinLock.h"
#include "thekogans/crypto/OpenSSLInit.h"
#include "thekogans/crypto/OpenSSLUtils.h"
#include "thekogans/stream/Config.h"

namespace thekogans {
    namespace stream {

        /// \struct SSL_CTXDeleter OpenSSLUtils.h thekogans/stream/OpenSSLUtils.h
        ///
        /// \brief
        /// Custom deleter for SSL_CTX.
        struct _LIB_THEKOGANS_STREAM_DECL SSL_CTXDeleter {
            /// \brief
            /// Called by unique_ptr::~unique_ptr.
            /// \param[in] ctx SSL_CTX to delete.
            void operator () (SSL_CTX *ctx);
        };
        /// \brief
        /// Convenient typedef for std::unique_ptr<SSL_CTX, SSL_CTXDeleter>.
        typedef std::unique_ptr<SSL_CTX, SSL_CTXDeleter> SSL_CTXPtr;

        /// \struct SSLDeleter OpenSSLUtils.h thekogans/stream/OpenSSLUtils.h
        ///
        /// \brief
        /// Custom deleter for SSL.
        struct _LIB_THEKOGANS_STREAM_DECL SSLDeleter {
            /// \brief
            /// Called by unique_ptr::~unique_ptr.
            /// \param[in] ssl SSL to delete.
            void operator () (SSL *ssl);
        };
        /// \brief
        /// Convenient typedef for std::unique_ptr<SSL, SSLDeleter>.
        typedef std::unique_ptr<SSL, SSLDeleter> SSLPtr;

        /// \struct SSL_SESSIONDeleter OpenSSLUtils.h thekogans/stream/OpenSSLUtils.h
        ///
        /// \brief
        /// Custom deleter for SSL_SESSION.
        struct _LIB_THEKOGANS_STREAM_DECL SSL_SESSIONDeleter {
            /// \brief
            /// Called by unique_ptr::~unique_ptr.
            /// \param[in] session SSL_SESSION to delete.
            void operator () (SSL_SESSION *session);
        };
        /// \brief
        /// Convenient typedef for std::unique_ptr<SSL_SESSION, SSL_SESSIONDeleter>.
        typedef std::unique_ptr<SSL_SESSION, SSL_SESSIONDeleter> SSL_SESSIONPtr;

        /// \struct OpenSSLInit OpenSSLUtils.h thekogans/stream/OpenSSLUtils.h
        ///
        /// \brief
        /// OpenSSLInit encapsulates the details of initializing the OpenSSL
        /// library. Instantiate one of these before making any calls in to
        /// the library proper.
        struct _LIB_THEKOGANS_STREAM_DECL OpenSSLInit : public crypto::OpenSSLInit {
            /// \brief
            /// Used by Secure[TCP | UDP]Socket to associate it's pointer with SSL.
            static int SSLSecureSocketIndex;
            /// \brief
            /// Used by SecureTCPSocket to associate it's SecureTCPSocket::SessionInfo
            /// pointer with SSL_SESSION.
            static int SSL_SESSIONSessionInfoIndex;
            /// \brief
            /// Synchronization lock.
            static util::SpinLock spinLock;

            /// \brief
            /// ctor.
            /// Initialize the Open SSL library.
            /// \param[in] multiThreaded true = initialize thread support.
            /// \param[in] entropyNeeded Number of entropy bytes to use to seed the PRNG.
            /// \param[in] workingSetSize Physical pages to reserve.
            /// \param[in] loadSystemCACertificates true == Call
            /// crypto::SystemCACertificates::Load (loadSystemRootCACertificatesOnly);
            /// \param[in] loadSystemRootCACertificatesOnly true == load only
            /// root CA (self signed) certificates.
            OpenSSLInit (
                bool multiThreaded = true,
                util::ui32 entropyNeeded = DEFAULT_ENTROPY_NEEDED,
                util::ui64 workingSetSize = DEFAULT_WORKING_SET_SIZE,
                bool loadSystemCACertificates = true,
                bool loadSystemRootCACertificatesOnly = true);

            /// \brief
            /// OpenSSLInit is neither copy constructable, nor assignable.
            THEKOGANS_STREAM_DISALLOW_COPY_AND_ASSIGN (OpenSSLInit)
        };

        /// \brief
        /// The following utilities aid in performing thekogans.net style of TLS.
        /// This style uses an xml configuration file to store certificates and
        /// other parameters. Please see examples/secure[tcp | udp]echo (specifically
        /// the mkcerts-[dsa | rsa] scripts) to learn how to do that.

        /// \struct SessionInfo OpenSSLInit.h thekogans/stream/OpenSSLInit.h
        ///
        /// \brief
        /// SessionInfo stores extended session info. Info that would
        /// not otherwise fit in to SSL_CTX. It's also used to retrieve
        /// the currently negotiated session state \see{SecureTCPSocket::GetSessionInfo}
        /// to be later passed back in to SecureTCPSocket::SessionConnect
        /// to attempt session resumption.
        struct _LIB_THEKOGANS_STREAM_DECL SessionInfo : public util::RefCounted {
            /// \brief
            /// Declare \see{RefCounted} pointers.
            THEKOGANS_UTIL_DECLARE_REF_COUNTED_POINTERS (SessionInfo)

            /// \brief
            /// SessionInfo has a private heap to help with memory
            /// management, performance, and global heap fragmentation.
            THEKOGANS_UTIL_DECLARE_HEAP_WITH_LOCK (SessionInfo, util::SpinLock)

            enum {
                /// \brief
                /// Default renegotiation frequency (in bytes).
                /// NOTE: This value aggregates both reads ands writes.
                DEFAULT_RENEGOTIATION_FREQUENCY = util::UI32_MAX
            };

            /// \brief
            /// "SessionInfo"
            static const char * const TAG_SESSION_INFO;
            /// \brief
            /// "ServerName"
            static const char * const ATTR_SERVER_NAME;
            /// \brief
            /// "RenegotiationFrequency"
            static const char * const ATTR_RENEGOTIATION_FREQUENCY;
            /// \brief
            /// "BidirectionalShutdown"
            static const char * const ATTR_BIDIRECTIONAL_SHUTDOWN;
            /// \brief
            /// "CountTransfered"
            static const char * const ATTR_COUNT_TRANSFERED;

            /// \brief
            /// On client it's SNI and the name to verify post connecton.
            std::string serverName;
            /// \brief
            /// How many bytes to transfer before initiating
            /// a session renegotiation.
            std::size_t renegotiationFrequency;
            /// \brief
            /// If true, perform bidirectional shutdown.
            bool bidirectionalShutdown;
            /// \brief
            /// Count of bytes transfered (both read and write).
            /// When it reaches renegotiationFrequency, a rehandshake
            /// will be initiated and the counter will be reset.
            std::size_t countTransfered;
            /// \brief
            /// Active session.
            SSL_SESSIONPtr session;

            /// \brief
            /// An empty SessionInfo.
            static const SessionInfo Empty;

            /// \brief
            /// ctor.
            /// \param[in] serverName_ Server name to validate..
            /// \param[in] renegotiationFrequency_ How many bytes to
            /// transfer before initiating a session renegotiation.
            /// \param[in] bidirectionalShutdown_ If true, perform
            /// bidirectional shutdown.
            /// \param[in] countTransfered_ Counter of bytes
            /// transfered (both read and write).
            SessionInfo (
                const std::string &serverName_ = std::string (),
                std::size_t renegotiationFrequency_ = DEFAULT_RENEGOTIATION_FREQUENCY,
                bool bidirectionalShutdown_ = true,
                std::size_t countTransfered_ = 0) :
                serverName (serverName_),
                renegotiationFrequency (renegotiationFrequency_),
                bidirectionalShutdown (bidirectionalShutdown_),
                countTransfered (countTransfered_) {}
            /// \brief
            /// ctor.
            /// \param[in] node pugi::xml_node representing
            /// a SecureTCPSocket::SessionInfo.
            SessionInfo (const pugi::xml_node &node) :
                    renegotiationFrequency (DEFAULT_RENEGOTIATION_FREQUENCY),
                    bidirectionalShutdown (true),
                    countTransfered (0) {
                Parse (node);
            }
            /// \brief
            /// Copy ctor.
            /// \param[in] sessionInfo SessionInfo to copy.
            SessionInfo (const SessionInfo &sessionInfo);

            /// \brief
            /// Assignement operator.
            /// \param[in] sessionInfo SessionInfo to copy.
            /// \return *this.
            SessionInfo &operator = (const SessionInfo &sessionInfo);

            /// \brief
            /// Parse a node representing a SecureTCPSocket::SessionInfo:
            /// <tagName ServerName = ""
            ///          RenegotiationFrequency = ""
            ///          BidirectionalShutdown = ""
            ///          CountTransfered = ""/>
            /// \param[in] node pugi::xml_node representing
            /// a SecureTCPSocket::SessionInfo.
            void Parse (const pugi::xml_node &node);
            /// \brief
            /// Return a string representing the rest
            /// state of the SecureTCPSocket::SessionInfo.
            /// \param[in] indentationLevel Pretty print parameter.
            /// indents the tag with 4 * indentationLevel spaces.
            /// \param[in] tagName Tag name (default to "SessionInfo").
            /// \return String representing the rest state of the
            /// SecureTCPSocket::SessionInfo.
            std::string ToString (
                std::size_t indentationLevel = 0,
                const char *tagName = TAG_SESSION_INFO) const;
        };

        /// \brief
        /// Maximum TLS record length.
        const std::size_t TLS_MAX_RECORD_LENGTH = 16384;

        /// \brief
        /// TLS version 1.0
        _LIB_THEKOGANS_STREAM_DECL extern const char * const OPENSSL_TLS_1_0;
        /// \brief
        /// TLS version 1.1
        _LIB_THEKOGANS_STREAM_DECL extern const char * const OPENSSL_TLS_1_1;
        /// \brief
        /// TLS version 1.2
        _LIB_THEKOGANS_STREAM_DECL extern const char * const OPENSSL_TLS_1_2;
        /// \brief
        /// Given a string representing a version, return the
        /// corresponding TLS method.
        /// \param[in] version One of OPENSSL_TLS_* strings.
        /// \return SSL_METHOD that supports the given version.
        _LIB_THEKOGANS_STREAM_DECL const SSL_METHOD * _LIB_THEKOGANS_STREAM_API
            GetTLSMethod (const std::string &version = OPENSSL_TLS_1_2);
        /// \brief
        /// DTLS version 1.0
        _LIB_THEKOGANS_STREAM_DECL extern const char * const OPENSSL_DTLS_1_0;
        /// \brief
        /// DTLS version 1.2
        _LIB_THEKOGANS_STREAM_DECL extern const char * const OPENSSL_DTLS_1_2;
        /// \brief
        /// Given a string representing a version, return the
        /// corresponding DTLS method.
        /// \param[in] version One of OPENSSL_DTLS_* strings.
        /// \return SSL_METHOD that supports the given version.
        _LIB_THEKOGANS_STREAM_DECL const SSL_METHOD * _LIB_THEKOGANS_STREAM_API
            GetDTLSMethod (const std::string &version = OPENSSL_DTLS_1_2);
        /// \brief
        /// Use this callback with SSL_set_verify if you want
        /// the failed handshake error report dumped to a log.
        /// \param[in] ok 1 = handshake succeeded, 0 = handshake failed.
        /// \param[in] store Certificate store to query about
        /// the failed handshake.
        /// \return ok
        _LIB_THEKOGANS_STREAM_DECL int
            VerifyCallback (
                int ok,
                X509_STORE_CTX *store);
        /// \brief
        /// Perform a simple post connection check. Make sure
        /// the handshake succeeded and the host name in the
        /// server certificate matches the given server name.
        /// \param[in] ssl An established connection to check.
        /// \param[in] serverName Server name to check.
        /// \return X509_V_OK = all is well,
        /// X509_V_ERR_APPLICATION_VERIFICATION = post connection check failed.
        _LIB_THEKOGANS_STREAM_DECL int _LIB_THEKOGANS_STREAM_API
            PostConnectionCheck (
                SSL *ssl,
                const std::string &serverName);
        /// \brief
        /// Load a PEM encoded CA certificate list.
        /// \param[in] ctx SSL_CTX to load the certificate in to.
        /// \param[in] caCertificates PEM encoded CA certificates.
        /// \param[in] passwordCallback Provide a password if PEM is encrypted.
        /// \param[in] userData User data for passwordCallback.
        _LIB_THEKOGANS_STREAM_DECL void _LIB_THEKOGANS_STREAM_API
            LoadCACertificates (
                SSL_CTX *ctx,
                const std::list<std::string> &caCertificates,
                pem_password_cb *passwordCallback = 0,
                void *userData = 0);
        /// \brief
        /// Load a PEM encoded certificate chain from a list of strings.
        /// \param[in] ctx SSL_CTX to load the certificates in to.
        /// \param[in] certificateChain List of strings representing a
        /// certificate chain.
        /// \param[in] passwordCallback Provide a password if PEM is encrypted.
        /// \param[in] userData User data for passwordCallback.
        _LIB_THEKOGANS_STREAM_DECL void _LIB_THEKOGANS_STREAM_API
            LoadCertificateChain (
                SSL_CTX *ctx,
                const std::list<std::string> &certificateChain,
                pem_password_cb *passwordCallback = 0,
                void *userData = 0);
        /// \brief
        /// Load a PEM encoded private key from a string.
        /// \param[in] ctx SSL_CTX to load the private key in to.
        /// \param[in] privateKey String representing a private key.
        /// \param[in] passwordCallback Provide a password if PEM is encrypted.
        /// \param[in] userData User data for passwordCallback.
        _LIB_THEKOGANS_STREAM_DECL void _LIB_THEKOGANS_STREAM_API
            LoadPrivateKey (
                SSL_CTX *ctx,
                const std::string &privateKey,
                pem_password_cb *passwordCallback = 0,
                void *userData = 0);
        /// \brief
        /// Load a ':' seperated cipher list key from a string.
        /// \param[in] ctx SSL_CTX to load the cipher list in to.
        /// \param[in] cipherList String representing a ':' seperated
        /// cipher list.
        _LIB_THEKOGANS_STREAM_DECL void _LIB_THEKOGANS_STREAM_API
            LoadCipherList (
                SSL_CTX *ctx,
                const std::string &cipherList);
        /// \brief
        /// Load a PEM encoded DH parameters from a string.
        /// \param[in] ctx SSL_CTX to load the DH parameters in to.
        /// \param[in] dhParams String representing DH parameters.
        /// \param[in] passwordCallback Provide a password if PEM is encrypted.
        /// \param[in] userData User data for passwordCallback.
        _LIB_THEKOGANS_STREAM_DECL void _LIB_THEKOGANS_STREAM_API
            LoadDHParams (
                SSL_CTX *ctx,
                const std::string &dhParams,
                pem_password_cb *passwordCallback = 0,
                void *userData = 0);
        /// \brief
        /// Load a PEM encoded ECDH parameters from a string.
        /// \param[in] ctx SSL_CTX to load the DH parameters in to.
        /// \param[in] ecdhParamsType String representing ECDH parameters
        /// type (auto | curve | pem).
        /// \param[in] ecdhParams String representing ECDH parameters.
        /// \param[in] passwordCallback Provide a password if PEM is encrypted.
        /// \param[in] userData User data for passwordCallback.
        _LIB_THEKOGANS_STREAM_DECL void _LIB_THEKOGANS_STREAM_API
            LoadECDHParams (
                SSL_CTX *ctx,
                const std::string &ecdhParamsType,
                const std::string &ecdhParams,
                pem_password_cb *passwordCallback = 0,
                void *userData = 0);

    } // namespace stream
} // namespace thekogans

#endif // defined (THEKOGANS_STREAM_HAVE_OPENSSL)

#endif // !defined (__thekogans_stream_OpenSSLUtils_h)
