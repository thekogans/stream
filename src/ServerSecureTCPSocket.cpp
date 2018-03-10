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

#if defined (THEKOGANS_STREAM_HAVE_OPENSSL)

#if defined (TOOLCHAIN_OS_Windows)
    #if !defined (_WINDOWS_)
        #if !defined (WIN32_LEAN_AND_MEAN)
            #define WIN32_LEAN_AND_MEAN
        #endif // !defined (WIN32_LEAN_AND_MEAN)
        #if !defined (NOMINMAX)
            #define NOMINMAX
        #endif // !defined (NOMINMAX)
    #endif // !defined (_WINDOWS_)
    #include <winsock2.h>
#endif // defined (TOOLCHAIN_OS_Windows)
#include <cassert>
#include <algorithm>
#if defined (THEKOGANS_STREAM_HAVE_PUGIXML)
    #include <sstream>
    #include "thekogans/util/XMLUtils.h"
#endif // defined (THEKOGANS_STREAM_HAVE_PUGIXML)
#include "thekogans/util/Exception.h"
#include "thekogans/util/RandomSource.h"
#include "thekogans/crypto/SystemCACertificates.h"
#include "thekogans/stream/AsyncIoEventQueue.h"
#include "thekogans/stream/AsyncIoEventSink.h"
#include "thekogans/stream/ServerSecureTCPSocket.h"

namespace thekogans {
    namespace stream {

        THEKOGANS_STREAM_IMPLEMENT_STREAM (ServerSecureTCPSocket)

    #if defined (THEKOGANS_STREAM_HAVE_PUGIXML)
        const char * const ServerSecureTCPSocket::Context::TLSContext::TAG_TLS_CONTEXT =
            "TLSContext";
        const char * const ServerSecureTCPSocket::Context::TLSContext::ATTR_PROTOCOL_VERSION =
            "ProtocolVersion";
        const char * const ServerSecureTCPSocket::Context::TLSContext::TAG_LOAD_SYSTEM_CA_CERTIFICATES =
            "LoadSystemCACertificates";
        const char * const ServerSecureTCPSocket::Context::TLSContext::TAG_CA_CERTIFICATES =
            "CACertificates";
        const char * const ServerSecureTCPSocket::Context::TLSContext::TAG_CERTIFICATE_CHAIN_RSA =
            "CertificateChainRSA";
        const char * const ServerSecureTCPSocket::Context::TLSContext::TAG_CERTIFICATE_CHAIN_DSA =
            "CertificateChainDSA";
        const char * const ServerSecureTCPSocket::Context::TLSContext::TAG_CERTIFICATE =
            "Certificate";
        const char * const ServerSecureTCPSocket::Context::TLSContext::TAG_PRIVATE_KEY_RSA =
            "PrivateKeyRSA";
        const char * const ServerSecureTCPSocket::Context::TLSContext::TAG_PRIVATE_KEY_DSA =
            "PrivateKeyDSA";
        const char * const ServerSecureTCPSocket::Context::TLSContext::TAG_CIPHER_LIST =
            "CipherList";
        const char * const ServerSecureTCPSocket::Context::TLSContext::TAG_REQUIRE_CLIENT_CERTIFICATE =
            "RequireClientCertificate";
        const char * const ServerSecureTCPSocket::Context::TLSContext::TAG_MAX_CLIENT_CERTIFICATE_CHAIN_DEPTH =
            "MaxClientCertificateChainDepth";
        const char * const ServerSecureTCPSocket::Context::TLSContext::TAG_DH_PARAMS =
            "DHParams";
        const char * const ServerSecureTCPSocket::Context::TLSContext::TAG_ECDH_PARAMS =
            "ECDHParams";
        const char * const ServerSecureTCPSocket::Context::TLSContext::ATTR_ECDH_PARAMS_TYPE =
            "Type";
        const char * const ServerSecureTCPSocket::Context::TLSContext::TAG_CACHED_SESSION_TTL =
            "CachedSessionTTL";
    #endif // defined (THEKOGANS_STREAM_HAVE_PUGIXML)

        ServerSecureTCPSocket::Context::TLSContext ServerSecureTCPSocket::Context::TLSContext::Empty;

        ServerSecureTCPSocket::Context::TLSContext::TLSContext (const TLSContext &context) :
                protocolVersion (context.protocolVersion),
                loadSystemCACertificates (context.loadSystemCACertificates),
                caCertificates (context.caCertificates),
                certificateChainRSA (context.certificateChainRSA),
                privateKeyRSA (context.privateKeyRSA),
                certificateChainDSA (context.certificateChainDSA),
                privateKeyDSA (context.privateKeyDSA),
                cipherList (context.cipherList),
                requireClientCertificate (context.requireClientCertificate),
                maxClientCertificateChainDepth (context.maxClientCertificateChainDepth),
                dhParams (context.dhParams),
                ecdhParamsType (context.ecdhParamsType),
                ecdhParams (context.ecdhParams),
                cachedSessionTTL (context.cachedSessionTTL),
                ctx (context.ctx.get ()) {
            if (ctx.get () != 0) {
                CRYPTO_add (&ctx->references, 1, CRYPTO_LOCK_SSL_CTX);
            }
        }

        ServerSecureTCPSocket::Context::TLSContext &ServerSecureTCPSocket::Context::TLSContext::operator = (
                const TLSContext &context) {
            if (&context != this) {
                protocolVersion = context.protocolVersion;
                loadSystemCACertificates = context.loadSystemCACertificates;
                caCertificates = context.caCertificates;
                certificateChainRSA = context.certificateChainRSA;
                privateKeyRSA = context.privateKeyRSA;
                certificateChainDSA = context.certificateChainDSA;
                privateKeyDSA = context.privateKeyDSA;
                cipherList = context.cipherList;
                requireClientCertificate = context.requireClientCertificate;
                maxClientCertificateChainDepth = context.maxClientCertificateChainDepth;
                dhParams = context.dhParams;
                ecdhParamsType = context.ecdhParamsType;
                ecdhParams = context.ecdhParams;
                cachedSessionTTL = context.cachedSessionTTL;
                ctx.reset (context.ctx.get ());
                if (ctx.get () != 0) {
                    CRYPTO_add (&ctx->references, 1, CRYPTO_LOCK_SSL_CTX);
                }
            }
            return *this;
        }

    #if defined (THEKOGANS_STREAM_HAVE_PUGIXML)
        void ServerSecureTCPSocket::Context::TLSContext::Parse (const pugi::xml_node &node) {
            protocolVersion = node.attribute (ATTR_PROTOCOL_VERSION).value ();
            for (pugi::xml_node child = node.first_child ();
                    !child.empty (); child = child.next_sibling ()) {
                if (child.type () == pugi::node_element) {
                    std::string childName = child.name ();
                    if (childName == TAG_LOAD_SYSTEM_CA_CERTIFICATES) {
                        loadSystemCACertificates =
                            util::Decodestring (child.text ().get ()) == util::XML_TRUE;
                    }
                    else if (childName == TAG_CA_CERTIFICATES) {
                        ParseCertificates (child, caCertificates);
                    }
                    else if (childName == TAG_CERTIFICATE_CHAIN_RSA) {
                        ParseCertificates (child, certificateChainRSA);
                    }
                    else if (childName == TAG_PRIVATE_KEY_RSA) {
                        privateKeyRSA = util::Decodestring (child.text ().get ());
                    }
                    else if (childName == TAG_CERTIFICATE_CHAIN_DSA) {
                        ParseCertificates (child, certificateChainDSA);
                    }
                    else if (childName == TAG_PRIVATE_KEY_DSA) {
                        privateKeyDSA = util::Decodestring (child.text ().get ());
                    }
                    else if (childName == TAG_CIPHER_LIST) {
                        cipherList = util::Decodestring (child.text ().get ());
                    }
                    else if (childName == TAG_REQUIRE_CLIENT_CERTIFICATE) {
                        requireClientCertificate =
                            util::Decodestring (child.text ().get ()) == util::XML_TRUE;
                    }
                    else if (childName == TAG_MAX_CLIENT_CERTIFICATE_CHAIN_DEPTH) {
                        maxClientCertificateChainDepth = util::stringToui32 (child.text ().get ());
                    }
                    else if (childName == TAG_DH_PARAMS) {
                        dhParams = util::Decodestring (child.text ().get ());
                    }
                    else if (childName == TAG_ECDH_PARAMS) {
                        ecdhParamsType = child.attribute (ATTR_ECDH_PARAMS_TYPE).value ();
                        ecdhParams = util::Decodestring (child.text ().get ());
                    }
                    else if (childName == TAG_CACHED_SESSION_TTL) {
                        cachedSessionTTL = util::stringToui32 (child.text ().get ());
                    }
                }
            }
            PrepareSSL_CTX ();
        }

        std::string ServerSecureTCPSocket::Context::TLSContext::ToString (
                util::ui32 indentationLevel,
                const char *tagName) const {
            if (tagName != 0) {
                util::Attributes attributes;
                attributes.push_back (
                    util::Attribute (
                        ATTR_PROTOCOL_VERSION,
                        util::Encodestring (protocolVersion)));
                util::Attributes ecdhParamsAttributes;
                ecdhParamsAttributes.push_back (
                    util::Attribute (
                        ATTR_ECDH_PARAMS_TYPE,
                        ecdhParamsType));
                std::ostringstream stream;
                stream <<
                    util::OpenTag (indentationLevel, tagName, attributes) <<
                        util::OpenTag (indentationLevel + 1, TAG_LOAD_SYSTEM_CA_CERTIFICATES) <<
                            (loadSystemCACertificates ? util::XML_TRUE : util::XML_FALSE) <<
                        util::CloseTag (indentationLevel + 1, TAG_LOAD_SYSTEM_CA_CERTIFICATES) <<
                        util::OpenTag (indentationLevel + 1, TAG_CA_CERTIFICATES) <<
                            FormatCertificates (indentationLevel + 2, caCertificates) <<
                        util::CloseTag (indentationLevel + 1, TAG_CA_CERTIFICATES) <<
                        util::OpenTag (indentationLevel + 1, TAG_CERTIFICATE_CHAIN_RSA) <<
                            FormatCertificates (indentationLevel + 2, certificateChainRSA) <<
                        util::CloseTag (indentationLevel + 1, TAG_CERTIFICATE_CHAIN_RSA) <<
                        util::OpenTag (indentationLevel + 1, TAG_PRIVATE_KEY_RSA) <<
                            util::Encodestring (privateKeyRSA) <<
                        util::CloseTag (indentationLevel + 1, TAG_PRIVATE_KEY_RSA) <<
                        util::OpenTag (indentationLevel + 1, TAG_CERTIFICATE_CHAIN_DSA) <<
                            FormatCertificates (indentationLevel + 2, certificateChainDSA) <<
                        util::CloseTag (indentationLevel + 1, TAG_CERTIFICATE_CHAIN_DSA) <<
                        util::OpenTag (indentationLevel + 1, TAG_PRIVATE_KEY_DSA) <<
                            util::Encodestring (privateKeyDSA) <<
                        util::CloseTag (indentationLevel + 1, TAG_PRIVATE_KEY_DSA) <<
                        util::OpenTag (indentationLevel + 1, TAG_CIPHER_LIST) <<
                            util::Encodestring (cipherList) <<
                        util::CloseTag (indentationLevel + 1, TAG_CIPHER_LIST) <<
                        util::OpenTag (indentationLevel + 1, TAG_REQUIRE_CLIENT_CERTIFICATE) <<
                            (requireClientCertificate ? util::XML_TRUE : util::XML_FALSE) <<
                        util::CloseTag (indentationLevel + 1, TAG_REQUIRE_CLIENT_CERTIFICATE) <<
                        util::OpenTag (indentationLevel + 1, TAG_MAX_CLIENT_CERTIFICATE_CHAIN_DEPTH) <<
                            util::ui32Tostring (maxClientCertificateChainDepth) <<
                        util::CloseTag (indentationLevel + 1, TAG_MAX_CLIENT_CERTIFICATE_CHAIN_DEPTH) <<
                        util::OpenTag (indentationLevel + 1, TAG_DH_PARAMS) <<
                            util::Encodestring (dhParams) <<
                        util::CloseTag (indentationLevel + 1, TAG_DH_PARAMS) <<
                        util::OpenTag (indentationLevel + 1, TAG_ECDH_PARAMS, ecdhParamsAttributes) <<
                            util::Encodestring (ecdhParams) <<
                        util::CloseTag (indentationLevel + 1, TAG_ECDH_PARAMS) <<
                        util::OpenTag (indentationLevel + 1, TAG_CACHED_SESSION_TTL) <<
                            util::ui32Tostring (cachedSessionTTL) <<
                        util::CloseTag (indentationLevel + 1, TAG_CACHED_SESSION_TTL) <<
                    util::CloseTag (indentationLevel, tagName);
                return stream.str ();
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }
    #endif // defined (THEKOGANS_STREAM_HAVE_PUGIXML)

        void ServerSecureTCPSocket::Context::TLSContext::PrepareSSL_CTX () {
            ctx.reset (SSL_CTX_new (GetTLSMethod (protocolVersion)));
            if (ctx.get () != 0) {
                if (loadSystemCACertificates) {
                    crypto::SystemCACertificates::Instance ().Use (ctx.get ());
                }
                if (!caCertificates.empty ()) {
                    LoadCACertificates (ctx.get (), caCertificates);
                }
                if (!certificateChainRSA.empty ()) {
                    LoadCertificateChain (ctx.get (), certificateChainRSA);
                    LoadPrivateKey (ctx.get (), privateKeyRSA);
                }
                if (!certificateChainDSA.empty ()) {
                    LoadCertificateChain (ctx.get (), certificateChainDSA);
                    LoadPrivateKey (ctx.get (), privateKeyDSA);
                }
                int mode = SSL_VERIFY_PEER;
                if (requireClientCertificate) {
                    mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
                }
                SSL_CTX_set_verify (ctx.get (), mode, VerifyCallback);
                SSL_CTX_set_verify_depth (ctx.get (), maxClientCertificateChainDepth);
                LoadCipherList (ctx.get (), cipherList);
                LoadDHParams (ctx.get (), dhParams);
                LoadECDHParams (ctx.get (), ecdhParamsType, ecdhParams);
                SSL_CTX_set_options (ctx.get (),
                    SSL_CTX_get_options (ctx.get ()) |
                    SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION |
                    SSL_OP_NO_TICKET);
                if (cachedSessionTTL > 0) {
                    util::ui8 sessionId[SSL_MAX_SSL_SESSION_ID_LENGTH] = {0};
                    {
                        util::RandomSource randomSource;
                        randomSource.GetBytes (sessionId, SSL_MAX_SSL_SESSION_ID_LENGTH);
                    }
                    if (SSL_CTX_set_session_id_context (
                            ctx.get (), sessionId, SSL_MAX_SSL_SESSION_ID_LENGTH) != 1) {
                        THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                    }
                    SSL_CTX_set_timeout (ctx.get (), cachedSessionTTL);
                }
                SSL_CTX_set_mode (ctx.get (), SSL_MODE_AUTO_RETRY);
            }
        }

        SSL_CTX *ServerSecureTCPSocket::Context::TLSContext::GetSSL_CTX () const {
            return ctx.get ();
        }

    #if defined (THEKOGANS_STREAM_HAVE_PUGIXML)
        void ServerSecureTCPSocket::Context::TLSContext::ParseCertificates (
                const pugi::xml_node &node,
                std::list<std::string> &certificates) {
            for (pugi::xml_node child = node.first_child ();
                    !child.empty (); child = child.next_sibling ()) {
                if (child.type () == pugi::node_element) {
                    std::string childName = child.name ();
                    if (childName == TAG_CERTIFICATE) {
                        std::string certificate = util::Decodestring (child.text ().get ());
                        if (!certificate.empty ()) {
                            certificates.push_back (certificate);
                        }
                    }
                }
            }
        }

        std::string ServerSecureTCPSocket::Context::TLSContext::FormatCertificates (
                util::ui32 indentationLevel,
                const std::list<std::string> &certificates) const {
            std::ostringstream stream;
            for (std::list<std::string>::const_iterator
                    it = certificates.begin (),
                    end = certificates.end (); it != end; ++it) {
                stream <<
                    util::OpenTag (indentationLevel, TAG_CERTIFICATE) <<
                        util::Encodestring (*it) <<
                    util::CloseTag (indentationLevel, TAG_CERTIFICATE);
            }
            return stream.str ();
        }

        const char * const ServerSecureTCPSocket::Context::VALUE_SERVER_SECURE_TCP_SOCKET =
            "ServerSecureTCPSocket";
        const char * const ServerSecureTCPSocket::Context::TAG_REUSE_ADDRESS =
            "ReuseAddress";
        const char * const ServerSecureTCPSocket::Context::TAG_MAX_PENDING_CONNECTIONS =
            "MaxPendingConnections";

        void ServerSecureTCPSocket::Context::Parse (const pugi::xml_node &node) {
            Stream::Context::Parse (node);
            for (pugi::xml_node child = node.first_child ();
                    !child.empty (); child = child.next_sibling ()) {
                if (child.type () == pugi::node_element) {
                    std::string childName = child.name ();
                    if (childName == Address::TAG_ADDRESS) {
                        address.Parse (child);
                    }
                    else if (childName == TAG_REUSE_ADDRESS) {
                        reuseAddress = std::string (child.text ().get ()) == util::XML_TRUE;
                    }
                    else if (childName == TAG_MAX_PENDING_CONNECTIONS) {
                        maxPendingConnections = util::stringToui32 (child.text ().get ());
                    }
                    else if (childName == TLSContext::TAG_TLS_CONTEXT) {
                        context.Parse (child);
                    }
                    else if (childName == SessionInfo::TAG_SESSION_INFO) {
                        sessionInfo.Parse (child);
                    }
                }
            }
            // Sanity check. Make sure that Context contained a "TLSContext" tag.
            assert (context.GetSSL_CTX () != 0);
        }

        std::string ServerSecureTCPSocket::Context::ToString (
                util::ui32 indentationLevel,
                const char *tagName) const {
            if (tagName != 0) {
                std::ostringstream stream;
                stream <<
                    Stream::Context::ToString (indentationLevel, tagName) <<
                        address.ToString (indentationLevel + 1) <<
                        util::OpenTag (indentationLevel + 1, TAG_REUSE_ADDRESS) <<
                            util::boolTostring (reuseAddress) <<
                        util::CloseTag (indentationLevel + 1, TAG_REUSE_ADDRESS) <<
                        util::OpenTag (indentationLevel + 1, TAG_MAX_PENDING_CONNECTIONS) <<
                            util::i32Tostring (maxPendingConnections) <<
                        util::CloseTag (indentationLevel + 1, TAG_MAX_PENDING_CONNECTIONS) <<
                        context.ToString (indentationLevel + 1) <<
                        sessionInfo.ToString (indentationLevel + 1) <<
                    util::CloseTag (indentationLevel, tagName);
                return stream.str ();
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }
    #endif // defined (THEKOGANS_STREAM_HAVE_PUGIXML)

        Stream::Ptr ServerSecureTCPSocket::Context::CreateStream () const {
            return Stream::Ptr (
                new ServerSecureTCPSocket (
                    address,
                    reuseAddress,
                    maxPendingConnections,
                    context.GetSSL_CTX (),
                    sessionInfo));
        }

        ServerSecureTCPSocket::ServerSecureTCPSocket (
                const Address &address,
                bool reuseAddress,
                util::ui32 maxPendingConnections,
                SSL_CTX *ctx_,
                const SessionInfo &sessionInfo_) :
                TCPSocket (address.GetFamily (), SOCK_STREAM, IPPROTO_TCP),
                ctx (ctx_),
                sessionInfo (sessionInfo_) {
            if (ctx.get () != 0) {
                CRYPTO_add (&ctx->references, 1, CRYPTO_LOCK_SSL_CTX);
                if (reuseAddress) {
                #if !defined (TOOLCHAIN_OS_Windows)
                    if (address.GetFamily () == AF_LOCAL) {
                        unlink (address.GetPath ().c_str ());
                    }
                    else {
                #endif // !define (TOOLCHAIN_OS_Windows)
                        SetReuseAddress (true);
                #if !defined (TOOLCHAIN_OS_Windows)
                    }
                #endif // !defined (TOOLCHAIN_OS_Windows)
                }
                Bind (address);
                Listen (maxPendingConnections);
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        SecureTCPSocket::Ptr ServerSecureTCPSocket::Accept () {
            SecureTCPSocket::Ptr connection;
            if (IsAsync ()) {
                connection = asyncInfo->eventSink.GetSecureTCPSocket (
                    (THEKOGANS_UTIL_HANDLE)TCPSocket::Accept ());
            }
            else {
                connection.Reset (new SecureTCPSocket (
                    (THEKOGANS_UTIL_HANDLE)TCPSocket::Accept ()));
            #if defined (TOOLCHAIN_OS_Windows)
                connection->UpdateAcceptContext (handle);
            #endif // defined (TOOLCHAIN_OS_Windows)
            }
            return connection;
        }

        void ServerSecureTCPSocket::InitAsyncIo () {
        #if defined (TOOLCHAIN_OS_Windows)
            PostAsyncAccept ();
        #else // defined (TOOLCHAIN_OS_Windows)
            SetBlocking (false);
            asyncInfo->AddStreamForEvents (AsyncInfo::EventRead);
        #endif // defined (TOOLCHAIN_OS_Windows)
        }

    #if defined (TOOLCHAIN_OS_Windows)
        void ServerSecureTCPSocket::HandleOverlapped (AsyncInfo::Overlapped &overlapped) throw () {
            if (overlapped.event == AsyncInfo::EventConnect) {
                THEKOGANS_UTIL_TRY {
                    PostAsyncAccept ();
                    TCPSocket::AcceptOverlapped &acceptOverlapped =
                        (TCPSocket::AcceptOverlapped &)overlapped;
                    TCPSocket::UpdateAcceptContext (handle,
                        (THEKOGANS_UTIL_HANDLE)acceptOverlapped.connection);
                    SecureTCPSocket::Ptr connection (
                        asyncInfo->eventSink.GetSecureTCPSocket (
                            (THEKOGANS_UTIL_HANDLE)acceptOverlapped.connection));
                    // AcceptOverlapped::~AcceptOverlapped will
                    // close an unclaimed socket. Set it to
                    // THEKOGANS_STREAM_INVALID_SOCKET to let
                    // it know that we did in fact claimed it.
                    acceptOverlapped.connection = THEKOGANS_STREAM_INVALID_SOCKET;
                    asyncInfo->eventSink.HandleServerSecureTCPSocketConnection (
                        *this, connection);
                }
                THEKOGANS_UTIL_CATCH (util::Exception) {
                    THEKOGANS_UTIL_EXCEPTION_NOTE_LOCATION (exception);
                    asyncInfo->eventSink.HandleStreamError (*this, exception);
                }
            }
        }
    #else // defined (TOOLCHAIN_OS_Windows)
        void ServerSecureTCPSocket::HandleAsyncEvent (util::ui32 event) throw () {
            if (event == AsyncInfo::EventRead) {
                THEKOGANS_UTIL_TRY {
                    SecureTCPSocket::Ptr connection = Accept ();
                    // Connections inherit the listening socket's
                    // non-blocking state. Since we handle all
                    // async io through AsyncIoEventQueue, set the
                    // connection to blocking. If the caller
                    // decides to make the connection async, they
                    // will call AsyncIoEventQueue::AddStream
                    // explicitly.
                    connection->SetBlocking (true);
                    asyncInfo->eventSink.HandleServerSecureTCPSocketConnection (
                        *this, connection);
                }
                THEKOGANS_UTIL_CATCH (util::Exception) {
                    THEKOGANS_UTIL_EXCEPTION_NOTE_LOCATION (exception);
                    asyncInfo->eventSink.HandleStreamError (*this, exception);
                }
            }
        }
    #endif // defined (TOOLCHAIN_OS_Windows)

    } // namespace stream
} // namespace thekogans

#endif // defined (THEKOGANS_STREAM_HAVE_OPENSSL)
