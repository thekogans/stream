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

#include <cassert>
#include <algorithm>
#include <sstream>
#include "thekogans/util/XMLUtils.h"
#include "thekogans/util/Exception.h"
#include "thekogans/util/RandomSource.h"
#include "thekogans/crypto/OpenSSLException.h"
#include "thekogans/stream/AsyncIoEventQueue.h"
#include "thekogans/stream/AsyncIoEventSink.h"
#include "thekogans/stream/ServerSecureUDPSocket.h"

namespace thekogans {
    namespace stream {

        THEKOGANS_STREAM_IMPLEMENT_STREAM (ServerSecureUDPSocket)

        const char * const ServerSecureUDPSocket::Context::DTLSContext::TAG_DTLS_CONTEXT =
            "DTLSContext";
        const char * const ServerSecureUDPSocket::Context::DTLSContext::ATTR_PROTOCOL_VERSION =
            "ProtocolVersion";
        const char * const ServerSecureUDPSocket::Context::DTLSContext::TAG_LOAD_SYSTEM_CA_CERTIFICATES =
            "LoadSystemCACertificates";
        const char * const ServerSecureUDPSocket::Context::DTLSContext::TAG_CA_CERTIFICATES =
            "CACertificates";
        const char * const ServerSecureUDPSocket::Context::DTLSContext::TAG_CERTIFICATE_CHAIN_RSA =
            "CertificateChainRSA";
        const char * const ServerSecureUDPSocket::Context::DTLSContext::TAG_CERTIFICATE_CHAIN_DSA =
            "CertificateChainDSA";
        const char * const ServerSecureUDPSocket::Context::DTLSContext::TAG_CERTIFICATE =
            "Certificate";
        const char * const ServerSecureUDPSocket::Context::DTLSContext::TAG_PRIVATE_KEY_RSA =
            "PrivateKeyRSA";
        const char * const ServerSecureUDPSocket::Context::DTLSContext::TAG_PRIVATE_KEY_DSA =
            "PrivateKeyDSA";
        const char * const ServerSecureUDPSocket::Context::DTLSContext::TAG_CIPHER_LIST =
            "CipherList";
        const char * const ServerSecureUDPSocket::Context::DTLSContext::TAG_REQUIRE_CLIENT_CERTIFICATE =
            "RequireClientCertificate";
        const char * const ServerSecureUDPSocket::Context::DTLSContext::TAG_MAX_CLIENT_CERTIFICATE_CHAIN_DEPTH =
            "MaxClientCertificateChainDepth";
        const char * const ServerSecureUDPSocket::Context::DTLSContext::TAG_DH_PARAMS =
            "DHParams";
        const char * const ServerSecureUDPSocket::Context::DTLSContext::TAG_ECDH_PARAMS =
            "ECDHParams";
        const char * const ServerSecureUDPSocket::Context::DTLSContext::ATTR_ECDH_PARAMS_TYPE =
            "Type";
        const char * const ServerSecureUDPSocket::Context::DTLSContext::TAG_CACHED_SESSION_TTL =
            "CachedSessionTTL";

        const ServerSecureUDPSocket::Context::DTLSContext ServerSecureUDPSocket::Context::DTLSContext::Empty;

        ServerSecureUDPSocket::Context::DTLSContext::DTLSContext (const DTLSContext &context) :
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

        ServerSecureUDPSocket::Context::DTLSContext &ServerSecureUDPSocket::Context::DTLSContext::operator = (
                const DTLSContext &context) {
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

        namespace {
            struct CookieFactory : public util::Singleton<CookieFactory, util::SpinLock> {
            private:
                enum {
                    COOKIE_SECRET_LENGTH = 16
                };
                util::ui8 cookieSecret[COOKIE_SECRET_LENGTH];

            public:
                CookieFactory () {
                    if (util::GlobalRandomSource::Instance ().GetBytes (
                            cookieSecret, COOKIE_SECRET_LENGTH) != COOKIE_SECRET_LENGTH) {
                        THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                            "Unable to get %u random bytes for cookie.",
                            COOKIE_SECRET_LENGTH);
                    }
                }

                void GetCookie (
                        const Address &address,
                        util::ui8 *cookie,
                        util::ui32 *cookieLength) const {
                    HMAC (EVP_sha1 (), cookieSecret, COOKIE_SECRET_LENGTH,
                        (const util::ui8 *)&address, address.length,
                        cookie, cookieLength);
                }
            };

            int CookieGenerateCB (
                    SSL *ssl,
                    util::ui8 *cookie,
                    util::ui32 *cookieLength) {
                Address peer;
                (void)BIO_dgram_get_peer (SSL_get_rbio (ssl), &peer);
                CookieFactory::Instance ().GetCookie (peer, cookie, cookieLength);
                return 1;
            }

            int CookieVerifyCB (
                    SSL *ssl,
                    util::ui8 *cookie,
                    util::ui32 cookieLength) {
                Address peer;
                (void)BIO_dgram_get_peer (SSL_get_rbio (ssl), &peer);
                unsigned char buffer[EVP_MAX_MD_SIZE] = {0};
                unsigned int bufferLength = 0;
                CookieFactory::Instance ().GetCookie (peer, buffer, &bufferLength);
                return bufferLength == cookieLength &&
                    memcmp (buffer, cookie, cookieLength) == 0 ? 1 : 0;
            }
        }

        void ServerSecureUDPSocket::Context::DTLSContext::Parse (const pugi::xml_node &node) {
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

        std::string ServerSecureUDPSocket::Context::DTLSContext::ToString (
                std::size_t indentationLevel,
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

        void ServerSecureUDPSocket::Context::DTLSContext::PrepareSSL_CTX () {
            ctx.reset (SSL_CTX_new (GetDTLSMethod (protocolVersion)));
            if (ctx.get () != 0) {
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
                    if (util::GlobalRandomSource::Instance ().GetBytes (
                            sessionId, SSL_MAX_SSL_SESSION_ID_LENGTH) == SSL_MAX_SSL_SESSION_ID_LENGTH) {
                        if (SSL_CTX_set_session_id_context (
                                ctx.get (), sessionId, SSL_MAX_SSL_SESSION_ID_LENGTH) != 1) {
                            THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                        }
                        SSL_CTX_set_timeout (ctx.get (), cachedSessionTTL);
                    }
                    else {
                        THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                            "Unable to get %u random bytes for session id.",
                            SSL_MAX_SSL_SESSION_ID_LENGTH);
                    }
                }
                SSL_CTX_set_mode (ctx.get (), SSL_MODE_AUTO_RETRY);
                SSL_CTX_set_read_ahead (ctx.get (), 1);
                SSL_CTX_set_cookie_generate_cb (ctx.get (), CookieGenerateCB);
                SSL_CTX_set_cookie_verify_cb (ctx.get (), CookieVerifyCB);
            }
        }

        SSL_CTX *ServerSecureUDPSocket::Context::DTLSContext::GetSSL_CTX () const {
            return ctx.get ();
        }

        void ServerSecureUDPSocket::Context::DTLSContext::ParseCertificates (
                const pugi::xml_node &node,
                Certificates &certificates) {
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

        std::string ServerSecureUDPSocket::Context::DTLSContext::FormatCertificates (
                std::size_t indentationLevel,
                const Certificates &certificateChain) const {
            std::ostringstream stream;
            for (Certificates::const_iterator it = certificateChain.begin (),
                    end = certificateChain.end (); it != end; ++it) {
                stream <<
                    util::OpenTag (indentationLevel, TAG_CERTIFICATE) <<
                        util::Encodestring (*it) <<
                    util::CloseTag (indentationLevel, TAG_CERTIFICATE);
            }
            return stream.str ();
        }

        const char * const ServerSecureUDPSocket::Context::VALUE_SERVER_SECURE_UDP_SOCKET =
            "ServerSecureUDPSocket";

        void ServerSecureUDPSocket::Context::Parse (const pugi::xml_node &node) {
            Stream::Context::Parse (node);
            for (pugi::xml_node child = node.first_child ();
                    !child.empty (); child = child.next_sibling ()) {
                if (child.type () == pugi::node_element) {
                    std::string childName = child.name ();
                    if (childName == Address::TAG_ADDRESS) {
                        address.Parse (child);
                    }
                    else if (childName == DTLSContext::TAG_DTLS_CONTEXT) {
                        context.Parse (child);
                    }
                    else if (childName == SessionInfo::TAG_SESSION_INFO) {
                        sessionInfo.Parse (child);
                    }
                }
            }
            // Sanity check. Make sure that Context contained a "DTLSContext" tag.
            assert (context.GetSSL_CTX () != 0);
        }

        std::string ServerSecureUDPSocket::Context::ToString (
                std::size_t indentationLevel,
                const char *tagName) const {
            if (tagName != 0) {
                std::ostringstream stream;
                stream <<
                    Stream::Context::ToString (indentationLevel, tagName) <<
                        address.ToString (indentationLevel + 1) <<
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

        Stream::Ptr ServerSecureUDPSocket::Context::CreateStream () const {
            return Stream::Ptr (
                new ServerSecureUDPSocket (
                    address,
                    context.GetSSL_CTX (),
                    sessionInfo));
        }

        ServerSecureUDPSocket::ServerSecureUDPSocket (
                const Address &address_,
                SSL_CTX *ctx_,
                const SessionInfo &sessionInfo_) :
                UDPSocket (address_.GetFamily (), SOCK_DGRAM, IPPROTO_UDP),
                address (address_),
                ctx (ctx_),
                sessionInfo (sessionInfo_) {
            if (ctx.get () != 0) {
                CRYPTO_add (&ctx->references, 1, CRYPTO_LOCK_SSL_CTX);
                SetReuseAddress (true);
            #if defined (SO_REUSEPORT) || defined (SO_REUSE_UNICASTPORT)
                SetReusePort (true);
            #endif // defined (SO_REUSEPORT) || defined (SO_REUSE_UNICASTPORT)
                Bind (address);
                SetRecvPktInfo (true);
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        SecureUDPSocket::Ptr ServerSecureUDPSocket::Accept () {
            SecureUDPSocket::Ptr connection;
            {
                util::Buffer buffer;
                if (IsAsync ()) {
                    buffer = asyncInfo->eventSink.GetBuffer (
                        *this, util::HostEndian, TLS_MAX_RECORD_LENGTH);
                }
                else {
                    buffer = util::Buffer (util::HostEndian, TLS_MAX_RECORD_LENGTH);
                }
                Address from;
                Address to;
                if (buffer.AdvanceWriteOffset (
                        ReadMsg (buffer.GetWritePtr (), TLS_MAX_RECORD_LENGTH, from, to)) > 0) {
                    connection = CreatePeerConnection (std::move (buffer), from, to);
                }
            }
            return connection;
        }

        void ServerSecureUDPSocket::InitAsyncIo () {
        #if defined (TOOLCHAIN_OS_Windows)
            PostAsyncReadMsg ();
        #else // defined (TOOLCHAIN_OS_Windows)
            SetBlocking (false);
            asyncInfo->AddStreamForEvents (AsyncInfo::EventReadMsg);
        #endif // defined (TOOLCHAIN_OS_Windows)
        }

    #if defined (TOOLCHAIN_OS_Windows)
        void ServerSecureUDPSocket::HandleOverlapped (AsyncInfo::Overlapped &overlapped) throw () {
            if (overlapped.event == AsyncInfo::EventReadMsg) {
                THEKOGANS_UTIL_TRY {
                    PostAsyncReadMsg ();
                    ReadMsgWriteMsgOverlapped &readMsgWriteMsgOverlapped =
                        (ReadMsgWriteMsgOverlapped &)overlapped;
                    if (readMsgWriteMsgOverlapped.buffer.IsEmpty ()) {
                        std::size_t bufferLength = GetDataAvailable ();
                        if (bufferLength != 0) {
                            readMsgWriteMsgOverlapped.buffer =
                                asyncInfo->eventSink.GetBuffer (
                                    *this, util::HostEndian, bufferLength);
                            readMsgWriteMsgOverlapped.buffer.AdvanceWriteOffset (
                                ReadMsg (
                                    readMsgWriteMsgOverlapped.buffer.GetWritePtr (),
                                    bufferLength,
                                    readMsgWriteMsgOverlapped.from,
                                    readMsgWriteMsgOverlapped.to));
                        }
                    }
                    if (!readMsgWriteMsgOverlapped.buffer.IsEmpty ()) {
                        asyncInfo->eventSink.HandleServerSecureUDPSocketConnection (*this,
                            CreatePeerConnection (
                                std::move (readMsgWriteMsgOverlapped.buffer),
                                readMsgWriteMsgOverlapped.from,
                                readMsgWriteMsgOverlapped.to));
                    }
                }
                THEKOGANS_UTIL_CATCH (util::Exception) {
                    THEKOGANS_UTIL_EXCEPTION_NOTE_LOCATION (exception);
                    asyncInfo->eventSink.HandleStreamError (*this, exception);
                }
            }
        }
    #else // defined (TOOLCHAIN_OS_Windows)
        void ServerSecureUDPSocket::HandleAsyncEvent (util::ui32 event) throw () {
            if (event == AsyncInfo::EventReadMsg) {
                THEKOGANS_UTIL_TRY {
                    std::size_t bufferSize = GetDataAvailable ();
                    if (bufferSize != 0) {
                        SecureUDPSocket::Ptr connection = Accept ();
                        // Connections inherit the listening socket's
                        // non-blocking state. Since we handle all
                        // async io through AsyncIoEventQueue, set the
                        // connection to blocking. If the caller
                        // decides to make the connection async, they
                        // will call AsyncIoEventQueue::AddStream
                        // explicitly.
                        connection->SetBlocking (true);
                        asyncInfo->eventSink.HandleServerSecureUDPSocketConnection (
                            *this, connection);
                    }
                }
                THEKOGANS_UTIL_CATCH (util::Exception) {
                    THEKOGANS_UTIL_EXCEPTION_NOTE_LOCATION (exception);
                    asyncInfo->eventSink.HandleStreamError (*this, exception);
                }
            }
        }
    #endif // defined (TOOLCHAIN_OS_Windows)

        SecureUDPSocket::Ptr ServerSecureUDPSocket::CreatePeerConnection (
                util::Buffer buffer,
                const Address &from,
                const Address &to) const {
            SecureUDPSocket::Ptr connection (
                new SecureUDPSocket (from.GetFamily (), SOCK_DGRAM, IPPROTO_UDP));
            connection->SetReuseAddress (true);
        #if defined (SO_REUSEPORT) || defined (SO_REUSE_UNICASTPORT)
            connection->SetReusePort (true);
        #endif // defined (SO_REUSEPORT) || defined (SO_REUSE_UNICASTPORT)
            connection->Bind (to);
            connection->Connect (from);
            connection->decryptList.push_back (std::move (buffer));
            return connection;
        }
    } // namespace stream
} // namespace thekogans

#endif // defined (THEKOGANS_STREAM_HAVE_OPENSSL)
