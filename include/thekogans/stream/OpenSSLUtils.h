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
#include <ctime>
#include <memory>
#include <string>
#include <list>
#if defined (THEKOGANS_STREAM_HAVE_PUGIXML)
    #include <pugixml.hpp>
#endif // defined (THEKOGANS_STREAM_HAVE_PUGIXML)
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include "thekogans/util/Types.h"
#include "thekogans/util/Heap.h"
#include "thekogans/util/RefCounted.h"
#include "thekogans/util/Buffer.h"
#include "thekogans/util/SpinLock.h"
#include "thekogans/util/Exception.h"
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

        /// \struct BIODeleter OpenSSLUtils.h thekogans/stream/OpenSSLUtils.h
        ///
        /// \brief
        /// Custom deleter for BIO.
        struct _LIB_THEKOGANS_STREAM_DECL BIODeleter {
            /// \brief
            /// Called by unique_ptr::~unique_ptr.
            /// \param[in] bio BIO to delete.
            void operator () (BIO *bio);
        };
        /// \brief
        /// Convenient typedef for std::unique_ptr<BIO, BIODeleter>.
        typedef std::unique_ptr<BIO, BIODeleter> BIOPtr;

        /// \struct X509Deleter OpenSSLUtils.h thekogans/stream/OpenSSLUtils.h
        ///
        /// \brief
        /// Custom deleter for X509.
        struct _LIB_THEKOGANS_STREAM_DECL X509Deleter {
            /// \brief
            /// Called by unique_ptr::~unique_ptr.
            /// \param[in] x509 X509 to delete.
            void operator () (X509 *x509);
        };
        /// \brief
        /// Convenient typedef for std::unique_ptr<X509, X509Deleter>.
        typedef std::unique_ptr<X509, X509Deleter> X509Ptr;

        /// \struct X509_STOREDeleter OpenSSLUtils.h thekogans/stream/OpenSSLUtils.h
        ///
        /// \brief
        /// Custom deleter for X509.
        struct _LIB_THEKOGANS_STREAM_DECL X509_STOREDeleter {
            /// \brief
            /// Called by unique_ptr::~unique_ptr.
            /// \param[in] store X509_STORE to delete.
            void operator () (X509_STORE *store);
        };
        /// \brief
        /// Convenient typedef for std::unique_ptr<X509_STORE, X509_STOREDeleter>.
        typedef std::unique_ptr<X509_STORE, X509_STOREDeleter> X509_STOREPtr;

        /// \struct DHDeleter OpenSSLUtils.h thekogans/stream/OpenSSLUtils.h
        ///
        /// \brief
        /// Custom deleter for DH.
        struct _LIB_THEKOGANS_STREAM_DECL DHDeleter {
            /// \brief
            /// Called by unique_ptr::~unique_ptr.
            /// \param[in] dh DH to delete.
            void operator () (DH *dh);
        };
        /// \brief
        /// Convenient typedef for std::unique_ptr<DH, DHDeleter>.
        typedef std::unique_ptr<DH, DHDeleter> DHPtr;

        /// \struct EVP_PKEYDeleter OpenSSLUtils.h thekogans/stream/OpenSSLUtils.h
        ///
        /// \brief
        /// Custom deleter for EVP_PKEY.
        struct _LIB_THEKOGANS_STREAM_DECL EVP_PKEYDeleter {
            /// \brief
            /// Called by unique_ptr::~unique_ptr.
            /// \param[in] key EVP_PKEY to delete.
            void operator () (EVP_PKEY *key);
        };
        /// \brief
        /// Convenient typedef for std::unique_ptr<EVP_PKEY, EVP_PKEYDeleter>.
        typedef std::unique_ptr<EVP_PKEY, EVP_PKEYDeleter> EVP_PKEYPtr;

        /// \struct EC_KEYDeleter OpenSSLUtils.h thekogans/stream/OpenSSLUtils.h
        ///
        /// \brief
        /// Custom deleter for EC_KEY.
        struct _LIB_THEKOGANS_STREAM_DECL EC_KEYDeleter {
            /// \brief
            /// Called by unique_ptr::~unique_ptr.
            /// \param[in] key EC_KEY to delete.
            void operator () (EC_KEY *key);
        };
        /// \brief
        /// Convenient typedef for std::unique_ptr<EC_KEY, EC_KEYDeleter>.
        typedef std::unique_ptr<EC_KEY, EC_KEYDeleter> EC_KEYPtr;

        /// \struct DSADeleter OpenSSLUtils.h thekogans/stream/OpenSSLUtils.h
        ///
        /// \brief
        /// Custom deleter for DSA.
        struct _LIB_THEKOGANS_STREAM_DECL DSADeleter {
            /// \brief
            /// Called by unique_ptr::~unique_ptr.
            /// \param[in] dsa DSA to delete.
            void operator () (DSA *dsa);
        };
        /// \brief
        /// Convenient typedef for std::unique_ptr<DSA, DSADeleter>.
        typedef std::unique_ptr<DSA, DSADeleter> DSAPtr;

        /// \struct OpenSSLInit OpenSSLUtils.h thekogans/stream/OpenSSLUtils.h
        ///
        /// \brief
        /// OpenSSLInit encapsulates the details of initializing the OpenSSL
        /// library. Instantiate one of these before making any calls in to
        /// the library proper.
        struct _LIB_THEKOGANS_STREAM_DECL OpenSSLInit {
            /// \brief
            /// Used by Secure[TCP | UDP]Socket to associate a it's pointer with SSL.
            static int SSLSecureSocketIndex;
            /// \brief
            /// Used by SecureTCPSocket to a SecureTCPSocket::SessionInfo
            /// pointer with SSL_SESSION.
            static int SSL_SESSIONSessionInfoIndex;

            enum {
                /// \brief
                /// Minimum entropy bytes to use for PRNG seeding
                /// (anything less than this would weaken the crypto).
                MIN_ENTROPY_NEEDED = 512,
                /// \brief
                /// Default entropy bytes to use for PRNG seeding.
                DEFAULT_ENTROPY_NEEDED = 1024
            };
            /// \brief
            /// ctor.
            /// Initialize the Open SSL library.
            /// \param[in] multiThreaded true = initialize thread support.
            /// \param[in] entropyNeeded Number of entropy bytes to use
            /// to seed the PRNG.
            OpenSSLInit (
                bool multiThreaded = true,
                util::ui32 entropyNeeded = DEFAULT_ENTROPY_NEEDED);
            /// \brief
            /// \dtor.
            ~OpenSSLInit ();

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
        struct _LIB_THEKOGANS_STREAM_DECL SessionInfo {
            /// \brief
            /// Convenient typedef for std::unique_ptr<SessionInfo>.
            typedef std::unique_ptr<SessionInfo> UniquePtr;

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
            util::ui32 renegotiationFrequency;
            /// \brief
            /// If true, perform bidirectional shutdown.
            bool bidirectionalShutdown;
            /// \brief
            /// Count of bytes transfered (both read and write).
            /// When it reaches renegotiationFrequency, a rehandshake
            /// will be initiated and the counter will be reset.
            util::ui32 countTransfered;
            /// \brief
            /// Active session.
            SSL_SESSIONPtr session;

            /// \brief
            /// An empty SessionInfo.
            static SessionInfo Empty;

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
                util::ui32 renegotiationFrequency_ = DEFAULT_RENEGOTIATION_FREQUENCY,
                bool bidirectionalShutdown_ = true,
                util::ui32 countTransfered_ = 0) :
                serverName (serverName_),
                renegotiationFrequency (renegotiationFrequency_),
                bidirectionalShutdown (bidirectionalShutdown_),
                countTransfered (countTransfered_) {}
        #if defined (THEKOGANS_STREAM_HAVE_PUGIXML)
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
        #endif // defined (THEKOGANS_STREAM_HAVE_PUGIXML)
            /// \brief
            /// Copy ctor.
            /// \param[in] sessionInfo SessionInfo to copy.
            SessionInfo (const SessionInfo &sessionInfo);

            /// \brief
            /// Assignement operator.
            /// \param[in] sessionInfo SessionInfo to copy.
            /// \return *this.
            SessionInfo &operator = (const SessionInfo &sessionInfo);

        #if defined (THEKOGANS_STREAM_HAVE_PUGIXML)
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
                util::ui32 indentationLevel = 0,
                const char *tagName = TAG_SESSION_INFO) const;
        #endif // defined (THEKOGANS_STREAM_HAVE_PUGIXML)
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
        _LIB_THEKOGANS_STREAM_DECL int VerifyCallback (
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
        /// Load a PEM encoded CA certificate from a string.
        /// \param[in] ctx SSL_CTX to load the certificate in to.
        /// \param[in] caCertificate String representing a CA certificate.
        /// \param[in] passwordCallback Provide a password if PEM is encrypted.
        /// \param[in] userData User data for passwordCallback.
        _LIB_THEKOGANS_STREAM_DECL void _LIB_THEKOGANS_STREAM_API
            LoadCACertificate (
                SSL_CTX *ctx,
                const std::string &caCertificate,
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
        /// \paparam[in] userData User data for passwordCallback.
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
        /// \brief
        /// Parse a PEM encoded certificate.
        /// \param[in] buffer Buffer containing the PEM encoded certificate.
        /// \param[in] length Length of buffer.
        /// \param[in] passwordCallback Provide a password if PEM is encrypted.
        /// \param[in] userData User data for passwordCallback.
        /// \return Parsed certificate.
        _LIB_THEKOGANS_STREAM_DECL X509Ptr _LIB_THEKOGANS_STREAM_API
            ParseCertificate (
                const void *buffer,
                std::size_t length,
                pem_password_cb *passwordCallback = 0,
                void *userData = 0);
        /// \brief
        /// Parse a PEM encoded public key.
        /// \param[in] buffer Buffer containing the PEM encoded public key.
        /// \param[in] length Length of buffer.
        /// \param[in] passwordCallback Provide a password if PEM is encrypted.
        /// \param[in] userData User data for passwordCallback.
        /// \return Parsed public key.
        _LIB_THEKOGANS_STREAM_DECL EVP_PKEYPtr _LIB_THEKOGANS_STREAM_API
            ParsePUBKEY (
                const void *buffer,
                std::size_t length,
                pem_password_cb *passwordCallback = 0,
                void *userData = 0);
        /// \brief
        /// Parse a PEM encoded private key.
        /// \param[in] buffer Buffer containing the PEM encoded private key.
        /// \param[in] length Length of buffer.
        /// \param[in] passwordCallback Provide a password if PEM is encrypted.
        /// \param[in] userData User data for passwordCallback.
        /// \return Parsed private key.
        _LIB_THEKOGANS_STREAM_DECL EVP_PKEYPtr _LIB_THEKOGANS_STREAM_API
            ParsePrivateKey (
                const void *buffer,
                std::size_t length,
                pem_password_cb *passwordCallback = 0,
                void *userData = 0);
        /// \brief
        /// Parse a PEM encoded DH parameters.
        /// \param[in] buffer Buffer containing the PEM encoded DH parameters.
        /// \param[in] length Length of buffer.
        /// \param[in] passwordCallback Provide a password if PEM is encrypted.
        /// \param[in] userData User data for passwordCallback.
        /// \return Parsed DH parameters.
        _LIB_THEKOGANS_STREAM_DECL DHPtr _LIB_THEKOGANS_STREAM_API
            ParseDHParams (
                const void *buffer,
                std::size_t length,
                pem_password_cb *passwordCallback = 0,
                void *userData = 0);
        /// \brief
        /// Parse a PEM encoded DSA parameters.
        /// \param[in] buffer Buffer containing the PEM encoded DSA parameters.
        /// \param[in] length Length of buffer.
        /// \param[in] passwordCallback Provide a password if PEM is encrypted.
        /// \param[in] userData User data for passwordCallback.
        /// \return Parsed DSA parameters.
        _LIB_THEKOGANS_STREAM_DECL DSAPtr _LIB_THEKOGANS_STREAM_API
            ParseDSAParams (
                const void *buffer,
                std::size_t length,
                pem_password_cb *passwordCallback = 0,
                void *userData = 0);

        /// \brief
        /// These extensions to \see{thekogans::util::Exception} allow
        /// OpenSSL errors to be treated uniformly just like all the rest.

        /// \brief
        /// Create an \see{thekogans::util::Exception} and traceback using
        /// OpenSSL's error stack.
        /// \param[in] file Translation unit.
        /// \param[in] function Function in the translation unit.
        /// \param[in] line Translation unit line number.
        /// \param[in] buildTime Translation unit build time.
        /// \param[in] message Extra message to add to the exception report.
        /// \return An \see{thekogans::util::Exception} and traceback.
        _LIB_THEKOGANS_STREAM_DECL util::Exception _LIB_THEKOGANS_STREAM_API
            CreateOpenSSLException (
                const char *file,
                const char *function,
                util::ui32 line,
                const char *buildTime,
                const char *message = "");

        /// \def THEKOGANS_STREAM_OPENSSL_EXCEPTION_EX(
        ///          file, function, line, buildTime)
        /// Build an Exception from OpenSSL error stack.
        #define THEKOGANS_STREAM_OPENSSL_EXCEPTION_EX(\
                file, function, line, buildTime)\
            thekogans::stream::CreateOpenSSLException (\
                file, function, line, buildTime)
        /// \def THEKOGANS_STREAM_OPENSSL_EXCEPTION
        /// Build an Exception from OpenSSL error stack.
        #define THEKOGANS_STREAM_OPENSSL_EXCEPTION\
            THEKOGANS_STREAM_OPENSSL_EXCEPTION_EX (\
                __FILE__, __FUNCTION__, __LINE__, __DATE__ " " __TIME__)

        /// \def THEKOGANS_STREAM_THROW_OPENSSL_EXCEPTION_EX(
        ///          file, function, line, buildTime)
        /// Throw an Exception from OpenSSL error stack.
        #define THEKOGANS_STREAM_THROW_OPENSSL_EXCEPTION_EX(\
                file, function, line, buildTime)\
            THEKOGANS_UTIL_DEBUG_BREAK\
            throw THEKOGANS_STREAM_OPENSSL_EXCEPTION_EX (\
                file, function, line, buildTime)
        /// \def THEKOGANS_STREAM_THROW_OPENSSL_EXCEPTION
        /// Throw an Exception from OpenSSL error stack.
        #define THEKOGANS_STREAM_THROW_OPENSSL_EXCEPTION\
            THEKOGANS_STREAM_THROW_OPENSSL_EXCEPTION_EX (\
                __FILE__, __FUNCTION__, __LINE__, __DATE__ " " __TIME__)

        /// \def THEKOGANS_STREAM_THROW_OPENSSL_EXCEPTION_EX(
        ///          file, function, line, buildTime)
        /// Throw an Exception from OpenSSL error stack.
        #define THEKOGANS_STREAM_THROW_OPENSSL_AND_MESSAGE_EXCEPTION_EX(\
                file, function, line, buildTime, format, ...)\
            THEKOGANS_UTIL_DEBUG_BREAK\
            throw thekogans::stream::CreateOpenSSLException (\
                file, function, line, buildTime,\
                thekogans::util::FormatString (format, __VA_ARGS__).c_str ())
        /// \def THEKOGANS_STREAM_THROW_OPENSSL_AND_MESSAGE_EXCEPTION(format, ...)
        /// Throw an Exception from OpenSSL error stack.
        #define THEKOGANS_STREAM_THROW_OPENSSL_AND_MESSAGE_EXCEPTION(\
                format, ...)\
            THEKOGANS_STREAM_THROW_OPENSSL_AND_MESSAGE_EXCEPTION_EX (\
                __FILE__, __FUNCTION__, __LINE__, __DATE__ " " __TIME__,\
                format, __VA_ARGS__)

    } // namespace stream
} // namespace thekogans

#endif // defined (THEKOGANS_STREAM_HAVE_OPENSSL)

#endif // !defined (__thekogans_stream_OpenSSLUtils_h)
