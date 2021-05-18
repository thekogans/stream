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
        #include <windows.h>
    #endif // !defined (_WINDOWS_)
    #include <winsock2.h>
#endif // defined (TOOLCHAIN_OS_Windows)
#include <sstream>
#include "thekogans/util/XMLUtils.h"
#include "thekogans/util/Exception.h"
#include "thekogans/crypto/SystemCACertificates.h"
#include "thekogans/crypto/OpenSSLException.h"
#include "thekogans/stream/ClientSecureTCPSocket.h"

namespace thekogans {
    namespace stream {

        THEKOGANS_STREAM_IMPLEMENT_STREAM (ClientSecureTCPSocket)

        const char * const ClientSecureTCPSocket::Context::TLSContext::TAG_TLS_CONTEXT =
            "TLSContext";
        const char * const ClientSecureTCPSocket::Context::TLSContext::ATTR_PROTOCOL_VERSION =
            "ProtocolVersion";
        const char * const ClientSecureTCPSocket::Context::TLSContext::TAG_LOAD_SYSTEM_CA_CERTIFICATES =
            "LoadSystemCACertificates";
        const char * const ClientSecureTCPSocket::Context::TLSContext::TAG_CA_CERTIFICATES =
            "CACertificates";
        const char * const ClientSecureTCPSocket::Context::TLSContext::TAG_CERTIFICATE_CHAIN =
            "CertificateChain";
        const char * const ClientSecureTCPSocket::Context::TLSContext::TAG_CERTIFICATE =
            "Certificate";
        const char * const ClientSecureTCPSocket::Context::TLSContext::TAG_PRIVATE_KEY =
            "PrivateKey";
        const char * const ClientSecureTCPSocket::Context::TLSContext::TAG_CIPHER_LIST =
            "CipherList";
        const char * const ClientSecureTCPSocket::Context::TLSContext::TAG_VERIFY_SERVER =
            "VerifyServer";
        const char * const ClientSecureTCPSocket::Context::TLSContext::TAG_MAX_SERVER_CERTIFICATE_CHAIN_DEPTH =
            "MaxServerCertificateChainDepth";

        const ClientSecureTCPSocket::Context::TLSContext ClientSecureTCPSocket::Context::TLSContext::Empty;

        ClientSecureTCPSocket::Context::TLSContext::TLSContext (const TLSContext &context) :
                protocolVersion (context.protocolVersion),
                loadSystemCACertificates (context.loadSystemCACertificates),
                caCertificates (context.caCertificates),
                certificateChain (context.certificateChain),
                privateKey (context.privateKey),
                cipherList (context.cipherList),
                verifyServer (context.verifyServer),
                maxServerCertificateChainDepth (context.maxServerCertificateChainDepth),
                ctx (context.ctx.get ()) {
            if (ctx.get () != 0) {
            #if OPENSSL_VERSION_NUMBER < 0x10100000L
                CRYPTO_add (&ctx->references, 1, CRYPTO_LOCK_SSL_CTX);
            #else // OPENSSL_VERSION_NUMBER < 0x10100000L
                SSL_CTX_up_ref (ctx.get ());
            #endif // OPENSSL_VERSION_NUMBER < 0x10100000L
            }
        }

        ClientSecureTCPSocket::Context::TLSContext &ClientSecureTCPSocket::Context::TLSContext::operator = (
                const TLSContext &context) {
            if (&context != this) {
                protocolVersion = context.protocolVersion;
                loadSystemCACertificates = context.loadSystemCACertificates;
                caCertificates = context.caCertificates;
                certificateChain = context.certificateChain;
                privateKey = context.privateKey;
                cipherList = context.cipherList;
                verifyServer = context.verifyServer;
                maxServerCertificateChainDepth = context.maxServerCertificateChainDepth;
                ctx.reset (context.ctx.get ());
                if (ctx.get () != 0) {
                #if OPENSSL_VERSION_NUMBER < 0x10100000L
                    CRYPTO_add (&ctx->references, 1, CRYPTO_LOCK_SSL_CTX);
                #else // OPENSSL_VERSION_NUMBER < 0x10100000L
                    SSL_CTX_up_ref (ctx.get ());
                #endif // OPENSSL_VERSION_NUMBER < 0x10100000L
                }
            }
            return *this;
        }

        void ClientSecureTCPSocket::Context::TLSContext::Parse (const pugi::xml_node &node) {
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
                    else if (childName == TAG_CERTIFICATE_CHAIN) {
                        ParseCertificates (child, certificateChain);
                    }
                    else if (childName == TAG_PRIVATE_KEY) {
                        privateKey = util::Decodestring (child.text ().get ());
                    }
                    else if (childName == TAG_CIPHER_LIST) {
                        cipherList = util::Decodestring (child.text ().get ());
                    }
                    else if (childName == TAG_VERIFY_SERVER) {
                        verifyServer = std::string (child.text ().get ()) == util::XML_TRUE;
                    }
                    else if (childName == TAG_MAX_SERVER_CERTIFICATE_CHAIN_DEPTH) {
                        maxServerCertificateChainDepth = util::stringToui32 (child.text ().get ());
                    }
                }
            }
            PrepareSSL_CTX ();
        }

        std::string ClientSecureTCPSocket::Context::TLSContext::ToString (
                std::size_t indentationLevel,
                const char *tagName) const {
            if (tagName != 0) {
                util::Attributes attributes;
                attributes.push_back (
                    util::Attribute (
                        ATTR_PROTOCOL_VERSION,
                        util::Encodestring (protocolVersion)));
                std::ostringstream stream;
                stream <<
                    util::OpenTag (indentationLevel, tagName, attributes) <<
                        util::OpenTag (indentationLevel + 1, TAG_LOAD_SYSTEM_CA_CERTIFICATES) <<
                            (loadSystemCACertificates ? util::XML_TRUE : util::XML_FALSE) <<
                        util::CloseTag (indentationLevel + 1, TAG_LOAD_SYSTEM_CA_CERTIFICATES) <<
                        util::OpenTag (indentationLevel + 1, TAG_CA_CERTIFICATES) <<
                            FormatCertificates (indentationLevel + 2, caCertificates) <<
                        util::CloseTag (indentationLevel + 1, TAG_CA_CERTIFICATES) <<
                        util::OpenTag (indentationLevel + 1, TAG_CERTIFICATE_CHAIN) <<
                            FormatCertificates (indentationLevel + 2, certificateChain) <<
                        util::CloseTag (indentationLevel + 1, TAG_CERTIFICATE_CHAIN) <<
                        util::OpenTag (indentationLevel + 1, TAG_PRIVATE_KEY) <<
                            util::Encodestring (privateKey) <<
                        util::CloseTag (indentationLevel + 1, TAG_PRIVATE_KEY) <<
                        util::OpenTag (indentationLevel + 1, TAG_CIPHER_LIST) <<
                            util::Encodestring (cipherList) <<
                        util::CloseTag (indentationLevel + 1, TAG_CIPHER_LIST) <<
                        util::OpenTag (indentationLevel + 1, TAG_VERIFY_SERVER) <<
                            (verifyServer ? util::XML_TRUE : util::XML_FALSE) <<
                        util::CloseTag (indentationLevel + 1, TAG_VERIFY_SERVER) <<
                        util::OpenTag (indentationLevel + 1, TAG_MAX_SERVER_CERTIFICATE_CHAIN_DEPTH) <<
                            util::ui32Tostring (maxServerCertificateChainDepth) <<
                        util::CloseTag (indentationLevel + 1, TAG_MAX_SERVER_CERTIFICATE_CHAIN_DEPTH) <<
                    util::CloseTag (indentationLevel, tagName);
                return stream.str ();
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        void ClientSecureTCPSocket::Context::TLSContext::PrepareSSL_CTX () {
            ctx.reset (SSL_CTX_new (GetTLSMethod (protocolVersion)));
            if (ctx.get () != 0) {
                if (loadSystemCACertificates) {
                    crypto::SystemCACertificates::Instance ().Use (ctx.get ());
                }
                if (!caCertificates.empty ()) {
                    LoadCACertificates (ctx.get (), caCertificates);
                }
                if (!certificateChain.empty ()) {
                    LoadCertificateChain (ctx.get (), certificateChain);
                }
                if (!privateKey.empty ()) {
                    LoadPrivateKey (ctx.get (), privateKey);
                }
                if (!cipherList.empty ()) {
                    LoadCipherList (ctx.get (), cipherList);
                }
                if (verifyServer) {
                    SSL_CTX_set_verify (ctx.get (), SSL_VERIFY_PEER, VerifyCallback);
                    SSL_CTX_set_verify_depth (ctx.get (), maxServerCertificateChainDepth);
                }
                SSL_CTX_set_mode (ctx.get (), SSL_MODE_AUTO_RETRY);
            }
            else {
                THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
            }
        }

        SSL_CTX *ClientSecureTCPSocket::Context::TLSContext::GetSSL_CTX () const {
            return ctx.get ();
        }

        void ClientSecureTCPSocket::Context::TLSContext::ParseCertificates (
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
                        else {
                            THEKOGANS_UTIL_LOG_SUBSYSTEM_WARNING (
                                THEKOGANS_STREAM,
                                "Encountered malformed %s tag.\n",
                                TAG_CERTIFICATE_CHAIN);
                        }
                    }
                }
            }
        }

        std::string ClientSecureTCPSocket::Context::TLSContext::FormatCertificates (
                std::size_t indentationLevel,
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

        const char * const ClientSecureTCPSocket::Context::VALUE_CLIENT_SECURE_TCP_SOCKET =
            "ClientSecureTCPSocket";

        void ClientSecureTCPSocket::Context::Parse (const pugi::xml_node &node) {
            Socket::Context::Parse (node);
            for (pugi::xml_node child = node.first_child ();
                    !child.empty (); child = child.next_sibling ()) {
                if (child.type () == pugi::node_element) {
                    std::string childName = child.name ();
                    if (childName == Address::TAG_ADDRESS) {
                        address.Parse (child);
                    }
                    else if (childName == Context::TLSContext::TAG_TLS_CONTEXT) {
                        context.Parse (child);
                    }
                    else if (childName == SessionInfo::TAG_SESSION_INFO) {
                        sessionInfo.Parse (child);
                    }
                }
            }
        }

        std::string ClientSecureTCPSocket::Context::ToString (
                std::size_t indentationLevel,
                const char *tagName) const {
            if (tagName != 0) {
                std::ostringstream stream;
                stream <<
                    Socket::Context::ToString (indentationLevel, tagName) <<
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

        Stream::SharedPtr ClientSecureTCPSocket::Context::CreateStream () const {
            return Stream::SharedPtr (
                new SecureTCPSocket (address.GetFamily (), SOCK_STREAM, 0));
        }

    } // namespace stream
} // namespace thekogans

#endif // defined (THEKOGANS_STREAM_HAVE_OPENSSL)
