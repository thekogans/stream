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
#if defined (THEKOGANS_STREAM_HAVE_PUGIXML)
    #include <sstream>
    #include "thekogans/util/XMLUtils.h"
#endif // defined (THEKOGANS_STREAM_HAVE_PUGIXML)
#include "thekogans/util/Exception.h"
#include "thekogans/crypto/SystemCACertificates.h"
#include "thekogans/crypto/OpenSSLException.h"
#include "thekogans/stream/ClientSecureUDPSocket.h"

namespace thekogans {
    namespace stream {

        THEKOGANS_STREAM_IMPLEMENT_STREAM (ClientSecureUDPSocket)

    #if defined (THEKOGANS_STREAM_HAVE_PUGIXML)
        const char * const ClientSecureUDPSocket::Context::DTLSContext::TAG_DTLS_CONTEXT =
            "DTLSContext";
        const char * const ClientSecureUDPSocket::Context::DTLSContext::ATTR_PROTOCOL_VERSION =
            "ProtocolVersion";
        const char * const ClientSecureUDPSocket::Context::DTLSContext::TAG_LOAD_SYSTEM_CA_CERTIFICATES =
            "LoadSystemCACertificates";
        const char * const ClientSecureUDPSocket::Context::DTLSContext::TAG_CA_CERTIFICATES =
            "CACertificates";
        const char * const ClientSecureUDPSocket::Context::DTLSContext::TAG_CERTIFICATE_CHAIN =
            "CertificateChain";
        const char * const ClientSecureUDPSocket::Context::DTLSContext::TAG_CERTIFICATE =
            "Certificate";
        const char * const ClientSecureUDPSocket::Context::DTLSContext::TAG_PRIVATE_KEY =
            "PrivateKey";
        const char * const ClientSecureUDPSocket::Context::DTLSContext::TAG_CIPHER_LIST =
            "CipherList";
        const char * const ClientSecureUDPSocket::Context::DTLSContext::TAG_VERIFY_SERVER =
            "VerifyServer";
        const char * const ClientSecureUDPSocket::Context::DTLSContext::TAG_MAX_SERVER_CERTIFICATE_CHAIN_DEPTH =
            "MaxServerCertificateChainDepth";
    #endif // defined (THEKOGANS_STREAM_HAVE_PUGIXML)

        ClientSecureUDPSocket::Context::DTLSContext ClientSecureUDPSocket::Context::DTLSContext::Empty;

        ClientSecureUDPSocket::Context::DTLSContext::DTLSContext (const DTLSContext &context) :
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
                CRYPTO_add (&ctx->references, 1, CRYPTO_LOCK_SSL_CTX);
            }
        }

        ClientSecureUDPSocket::Context::DTLSContext &ClientSecureUDPSocket::Context::DTLSContext::operator = (
                const DTLSContext &context) {
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
                    CRYPTO_add (&ctx->references, 1, CRYPTO_LOCK_SSL_CTX);
                }
            }
            return *this;
        }

    #if defined (THEKOGANS_STREAM_HAVE_PUGIXML)
        void ClientSecureUDPSocket::Context::DTLSContext::Parse (const pugi::xml_node &node) {
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

        std::string ClientSecureUDPSocket::Context::DTLSContext::ToString (
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
    #endif // defined (THEKOGANS_STREAM_HAVE_PUGIXML)

        void ClientSecureUDPSocket::Context::DTLSContext::PrepareSSL_CTX () {
            ctx.reset (SSL_CTX_new (GetDTLSMethod (protocolVersion)));
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
                SSL_CTX_set_read_ahead (ctx.get (), 1);
            }
            else {
                THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
            }
        }

        SSL_CTX *ClientSecureUDPSocket::Context::DTLSContext::GetSSL_CTX () const {
            return ctx.get ();
        }

    #if defined (THEKOGANS_STREAM_HAVE_PUGIXML)
        void ClientSecureUDPSocket::Context::DTLSContext::ParseCertificates (
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

        std::string ClientSecureUDPSocket::Context::DTLSContext::FormatCertificates (
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

        const char * const ClientSecureUDPSocket::Context::VALUE_CLIENT_SECURE_UDP_SOCKET =
            "ClientSecureUDPSocket";

        void ClientSecureUDPSocket::Context::Parse (const pugi::xml_node &node) {
            Stream::Context::Parse (node);
            for (pugi::xml_node child = node.first_child ();
                    !child.empty (); child = child.next_sibling ()) {
                if (child.type () == pugi::node_element) {
                    std::string childName = child.name ();
                    if (childName == Address::TAG_ADDRESS) {
                        address.Parse (child);
                    }
                    else if (childName == Context::DTLSContext::TAG_DTLS_CONTEXT) {
                        context.Parse (child);
                    }
                    else if (childName == SessionInfo::TAG_SESSION_INFO) {
                        sessionInfo.Parse (child);
                    }
                }
            }
        }

        std::string ClientSecureUDPSocket::Context::ToString (
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
    #endif // defined (THEKOGANS_STREAM_HAVE_PUGIXML)

        Stream::Ptr ClientSecureUDPSocket::Context::CreateStream () const {
            return Stream::Ptr (
                new SecureUDPSocket (address.GetFamily (), SOCK_DGRAM, IPPROTO_UDP));
        }

    } // namespace stream
} // namespace thekogans

#endif // defined (THEKOGANS_STREAM_HAVE_OPENSSL)
