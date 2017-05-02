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

#if defined (THEKOGANS_STREAM_HAVE_PUGIXML) && defined (THEKOGANS_STREAM_HAVE_OPENSSL)

#include <cassert>
#include <sstream>
#include "thekogans/util/Exception.h"
#include "thekogans/util/XMLUtils.h"
#include "thekogans/stream/OpenSSLUtils.h"
#include "thekogans/stream/ClientSecureUDPSocket.h"

namespace thekogans {
    namespace stream {

        THEKOGANS_STREAM_IMPLEMENT_STREAM (ClientSecureUDPSocket)

        const char * const ClientSecureUDPSocket::OpenInfo::DTLSContext::TAG_DTLS_CONTEXT =
            "DTLSContext";
        const char * const ClientSecureUDPSocket::OpenInfo::DTLSContext::ATTR_PROTOCOL_VERSION =
            "ProtocolVersion";
        const char * const ClientSecureUDPSocket::OpenInfo::DTLSContext::TAG_CA_CERTIFICATE =
            "CACertificate";
        const char * const ClientSecureUDPSocket::OpenInfo::DTLSContext::TAG_CERTIFICATE_CHAIN =
            "CertificateChain";
        const char * const ClientSecureUDPSocket::OpenInfo::DTLSContext::TAG_CERTIFICATE =
            "Certificate";
        const char * const ClientSecureUDPSocket::OpenInfo::DTLSContext::TAG_PRIVATE_KEY =
            "PrivateKey";
        const char * const ClientSecureUDPSocket::OpenInfo::DTLSContext::TAG_CIPHER_LIST =
            "CipherList";
        const char * const ClientSecureUDPSocket::OpenInfo::DTLSContext::TAG_MAX_SERVER_CERTIFICATE_CHAIN_DEPTH =
            "MaxServerCertificateChainDepth";

        ClientSecureUDPSocket::OpenInfo::DTLSContext ClientSecureUDPSocket::OpenInfo::DTLSContext::Empty;

        ClientSecureUDPSocket::OpenInfo::DTLSContext::DTLSContext (const DTLSContext &context) :
                protocolVersion (context.protocolVersion),
                caCertificate (context.caCertificate),
                certificateChain (context.certificateChain),
                privateKey (context.privateKey),
                cipherList (context.cipherList),
                maxServerCertificateChainDepth (context.maxServerCertificateChainDepth),
                ctx (context.ctx.get ()) {
            if (ctx.get () != 0) {
                CRYPTO_add (&ctx->references, 1, CRYPTO_LOCK_SSL_CTX);
            }
        }

        ClientSecureUDPSocket::OpenInfo::DTLSContext &ClientSecureUDPSocket::OpenInfo::DTLSContext::operator = (
                const DTLSContext &context) {
            if (&context != this) {
                protocolVersion = context.protocolVersion;
                caCertificate = context.caCertificate;
                certificateChain = context.certificateChain;
                privateKey = context.privateKey;
                cipherList = context.cipherList;
                maxServerCertificateChainDepth = context.maxServerCertificateChainDepth;
                ctx.reset (context.ctx.get ());
                if (ctx.get () != 0) {
                    CRYPTO_add (&ctx->references, 1, CRYPTO_LOCK_SSL_CTX);
                }
            }
            return *this;
        }

        void ClientSecureUDPSocket::OpenInfo::DTLSContext::Parse (const pugi::xml_node &node) {
            protocolVersion = node.attribute (ATTR_PROTOCOL_VERSION).value ();
            for (pugi::xml_node child = node.first_child ();
                    !child.empty (); child = child.next_sibling ()) {
                if (child.type () == pugi::node_element) {
                    std::string childName = child.name ();
                    if (childName == TAG_CA_CERTIFICATE) {
                        caCertificate = util::Decodestring (child.text ().get ());
                    }
                    else if (childName == TAG_CERTIFICATE_CHAIN) {
                        ParseCertificateChain (child);
                    }
                    else if (childName == TAG_PRIVATE_KEY) {
                        privateKey = util::Decodestring (child.text ().get ());
                    }
                    else if (childName == TAG_CIPHER_LIST) {
                        cipherList = util::Decodestring (child.text ().get ());
                    }
                    else if (childName == TAG_MAX_SERVER_CERTIFICATE_CHAIN_DEPTH) {
                        maxServerCertificateChainDepth = util::stringToui32 (child.text ().get ());
                    }
                }
            }
            ctx.reset (SSL_CTX_new (GetDTLSMethod (protocolVersion)));
            if (ctx.get () != 0) {
                LoadCACertificate (ctx.get (), caCertificate);
                LoadCertificateChain (ctx.get (), certificateChain);
                LoadPrivateKey (ctx.get (), privateKey);
                SSL_CTX_set_verify (ctx.get (), SSL_VERIFY_PEER, VerifyCallback);
                SSL_CTX_set_verify_depth (ctx.get (), maxServerCertificateChainDepth);
                LoadCipherList (ctx.get (), cipherList);
                SSL_CTX_set_mode (ctx.get (), SSL_MODE_AUTO_RETRY);
                SSL_CTX_set_read_ahead (ctx.get (), 1);
            }
            else {
                THEKOGANS_STREAM_THROW_OPENSSL_EXCEPTION;
            }
        }

        std::string ClientSecureUDPSocket::OpenInfo::DTLSContext::ToString (
                util::ui32 indentationLevel,
                const char *tagName) const {
            assert (tagName != 0);
            util::Attributes attributes;
            attributes.push_back (
                util::Attribute (
                    ATTR_PROTOCOL_VERSION,
                    util::Encodestring (protocolVersion)));
            std::ostringstream stream;
            stream <<
                util::OpenTag (indentationLevel, tagName, attributes) <<
                    util::OpenTag (indentationLevel + 1, TAG_CA_CERTIFICATE) <<
                        FormatCertificateChain (indentationLevel + 2) <<
                    util::CloseTag (indentationLevel + 1, TAG_CA_CERTIFICATE) <<
                    util::OpenTag (indentationLevel + 1, TAG_CERTIFICATE_CHAIN) <<
                        FormatCertificateChain (indentationLevel + 2) <<
                    util::CloseTag (indentationLevel + 1, TAG_CERTIFICATE_CHAIN) <<
                    util::OpenTag (indentationLevel + 1, TAG_PRIVATE_KEY) <<
                        util::Encodestring (privateKey) <<
                    util::CloseTag (indentationLevel + 1, TAG_PRIVATE_KEY) <<
                    util::OpenTag (indentationLevel + 1, TAG_CIPHER_LIST) <<
                        util::Encodestring (cipherList) <<
                    util::CloseTag (indentationLevel + 1, TAG_CIPHER_LIST) <<
                    util::OpenTag (indentationLevel + 1, TAG_MAX_SERVER_CERTIFICATE_CHAIN_DEPTH) <<
                        util::ui32Tostring (maxServerCertificateChainDepth) <<
                    util::CloseTag (indentationLevel + 1, TAG_MAX_SERVER_CERTIFICATE_CHAIN_DEPTH) <<
                util::CloseTag (indentationLevel, tagName);
            return stream.str ();
        }

        SSL_CTX *ClientSecureUDPSocket::OpenInfo::DTLSContext::GetSSL_CTX () const {
            return ctx.get ();
        }

        void ClientSecureUDPSocket::OpenInfo::DTLSContext::ParseCertificateChain (
                const pugi::xml_node &node) {
            for (pugi::xml_node child = node.first_child ();
                    !child.empty (); child = child.next_sibling ()) {
                if (child.type () == pugi::node_element) {
                    std::string childName = child.name ();
                    if (childName == TAG_CERTIFICATE) {
                        std::string certificate = util::Decodestring (child.text ().get ());
                        if (!certificate.empty ()) {
                            certificateChain.push_back (certificate);
                        }
                    }
                }
            }
        }

        std::string ClientSecureUDPSocket::OpenInfo::DTLSContext::FormatCertificateChain (
                util::ui32 indentationLevel) const {
            std::ostringstream stream;
            for (std::list<std::string>::const_iterator it = certificateChain.begin (),
                    end = certificateChain.end (); it != end; ++it) {
                stream <<
                    util::OpenTag (indentationLevel, TAG_CERTIFICATE) <<
                        util::Encodestring (*it) <<
                    util::CloseTag (indentationLevel, TAG_CERTIFICATE);
            }
            return stream.str ();
        }


        const char * const ClientSecureUDPSocket::OpenInfo::VALUE_CLIENT_SECURE_UDP_SOCKET =
            "ClientSecureUDPSocket";

        void ClientSecureUDPSocket::OpenInfo::Parse (const pugi::xml_node &node) {
            Stream::OpenInfo::Parse (node);
            for (pugi::xml_node child = node.first_child ();
                    !child.empty (); child = child.next_sibling ()) {
                if (child.type () == pugi::node_element) {
                    std::string childName = child.name ();
                    if (childName == Address::TAG_ADDRESS) {
                        address.Parse (child);
                    }
                    else if (childName == OpenInfo::DTLSContext::TAG_DTLS_CONTEXT) {
                        context.Parse (child);
                    }
                    else if (childName == SessionInfo::TAG_SESSION_INFO) {
                        sessionInfo.Parse (child);
                    }
                }
            }
        }

        std::string ClientSecureUDPSocket::OpenInfo::ToString (
                util::ui32 indentationLevel,
                const char *tagName) const {
            assert (tagName != 0);
            std::ostringstream stream;
            stream <<
                Stream::OpenInfo::ToString (indentationLevel, tagName) <<
                    address.ToString (indentationLevel + 1) <<
                    context.ToString (indentationLevel + 1) <<
                    sessionInfo.ToString (indentationLevel + 1) <<
                util::CloseTag (indentationLevel, tagName);
            return stream.str ();
        }

        Stream::Ptr ClientSecureUDPSocket::OpenInfo::CreateStream () const {
            return Stream::Ptr (
                new SecureUDPSocket (address.GetFamily (), SOCK_DGRAM, IPPROTO_UDP));
        }

    } // namespace stream
} // namespace thekogans

#endif // defined (THEKOGANS_STREAM_HAVE_PUGIXML) && defined (THEKOGANS_STREAM_HAVE_OPENSSL)
