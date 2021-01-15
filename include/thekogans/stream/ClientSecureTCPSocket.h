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

#if !defined (__thekogans_stream_ClientSecureTCPSocket_h)
#define __thekogans_stream_ClientSecureTCPSocket_h

#if defined (THEKOGANS_STREAM_HAVE_OPENSSL)

#include <string>
#include <list>
#include "pugixml/pugixml.hpp"
#include "thekogans/util/Types.h"
#include "thekogans/stream/Config.h"
#include "thekogans/stream/SecureTCPSocket.h"
#include "thekogans/stream/OpenSSLUtils.h"

namespace thekogans {
    namespace stream {

        /// \struct ClientSecureTCPSocket ClientSecureTCPSocket.h thekogans/stream/ClientSecureTCPSocket.h
        ///
        /// \brief
        /// ClientSecureTCPSocket's sole reason for being is to expose ClientSecureTCPSocket::Context.
        /// All the heavy lifting is done by \see{SecureTCPSocket}.

        struct _LIB_THEKOGANS_STREAM_DECL ClientSecureTCPSocket : public SecureTCPSocket {
            /// \brief
            /// ClientSecureTCPSocket participates in the Stream dynamic
            /// discovery and creation.
            THEKOGANS_STREAM_DECLARE_STREAM (ClientSecureTCPSocket)

            /// \struct ClientSecureTCPSocket::Context ClientSecureTCPSocket.h
            /// thekogans/stream/ClientSecureTCPSocket.h
            ///
            /// \brief
            /// ClientSecureTCPSocket::Context represents the state
            /// of a ClientSecureTCPSocket at rest. At any time you want
            /// to reconstitute a ClientSecureTCPSocket from rest,
            /// feed a parsed (pugi::xml_node) one of:
            /// <tagName StreamType = "ClientSecureTCPSocket"
            ///          Family = ""
            ///          Type = ""
            ///          Protocol = "">
            ///     <Address Family = "inet | inet6"
            ///              Port = ""
            ///              Addr = "an inet or inet6 formated address, or host name"/>
            ///     <TLSContext ProtocolVersion = "1.0, 1.1, 1.2...">
            ///         <LoadSystemCACertificates>
            ///             true = Load system CA certificates.
            ///         </LoadSystemCACertificates>
            ///         <CACertificates>
            ///             <Certificate>
            ///                 CA certificate.
            ///             </Certificate>
            ///             ...
            ///         </CACertificates>
            ///         <CertificateChain>
            ///             <Certificate>
            ///                 Chain certificate.
            ///             </Certificate>
            ///             ...
            ///         </CertificateChain>
            ///         <PrivateKey Type = "RSA or DSA">
            ///             Private key associated with this certificate.
            ///         </PrivateKey>
            ///         <CipherList>':' separated cipher list.</CipherList>
            ///         <VerifyServer>
            ///             true = Verify server certificate.
            ///         </VerifyServer>
            ///         <MaxServerCertificateChainDepth>
            ///             Max depth of server certificate chain to verify.
            ///         </MaxServerCertificateChainDepth>
            ///     </TLSContext>
            ///     <SessionInfo ServerName = "Server name to validate."
            ///                  RenegotiationFrequency = "Count of bytes before forcing the server"
            ///                                           "to renegotiate (util::UI32_MAX = never)"
            ///                  BidirectionalShutdown = "If true, perform bidirectional shutdown."
            ///                  CountTransfered = "Count of bytes transfered (read and write)."/>
            /// </tagName>
            /// to: Stream::GetContext (const pugi::xml_node &node), and it
            /// will return back to you a properly constructed and initialized
            /// ClientSecureTCPSocket::Context. Call Context::CreateStream () to
            /// recreate a ClientSecureTCPSocket from rest. Where you go with
            /// it from there is entirely up to you, but may I recommend:
            /// \see{AsyncIoEventQueue}.
            struct _LIB_THEKOGANS_STREAM_DECL Context : public Socket::Context {
                /// \brief
                /// Convenient typedef for util::RefCounted::SharedPtr<Context>.
                typedef util::RefCounted::SharedPtr<Context> SharedPtr;

                /// \brief
                /// "ClientSecureTCPSocket".
                static const char * const VALUE_CLIENT_SECURE_TCP_SOCKET;

                /// \brief
                /// Address to connect to.
                Address address;
                /// \struct ClientSecureTCPSocket::Context::TLSContext ClientSecureTCPSocket.h
                /// thekogans/stream/ClientSecureTCPSocket.h
                ///
                /// \brief
                /// TLSContext aggregates parameters necessary to create a client side SSL_CTX.
                struct _LIB_THEKOGANS_STREAM_DECL TLSContext {
                    /// \brief
                    /// "TLSContext"
                    static const char * const TAG_TLS_CONTEXT;
                    /// \brief
                    /// "ProtocolVersion"
                    static const char * const ATTR_PROTOCOL_VERSION;
                    /// \brief
                    /// "LoadSystemCACertificates"
                    static const char * const TAG_LOAD_SYSTEM_CA_CERTIFICATES;
                    /// \brief
                    /// "CACertificates"
                    static const char * const TAG_CA_CERTIFICATES;
                    /// \brief
                    /// "CertificateChain"
                    static const char * const TAG_CERTIFICATE_CHAIN;
                    /// \brief
                    /// "Certificate"
                    static const char * const TAG_CERTIFICATE;
                    /// \brief
                    /// "PrivateKey"
                    static const char * const TAG_PRIVATE_KEY;
                    /// \brief
                    /// "Type"
                    static const char * const ATTR_PRIVATE_KEY_TYPE;
                    /// \brief
                    /// "CipherList"
                    static const char * const TAG_CIPHER_LIST;
                    /// \brief
                    /// "VerifyServer"
                    static const char * const TAG_VERIFY_SERVER;
                    /// \brief
                    /// "MaxServerCertificateChainDepth"
                    static const char * const TAG_MAX_SERVER_CERTIFICATE_CHAIN_DEPTH;

                    enum {
                        /// \brief
                        /// Default max server certificate chain depth.
                        DEFAULT_MAX_SERVER_CERTIFICATE_CHAIN_DEPTH = 4,
                    };

                    /// \brief
                    /// TLS protocol version.
                    std::string protocolVersion;
                    /// \brief
                    /// true = Load system CA certificates.
                    bool loadSystemCACertificates;
                    /// \brief
                    /// CA certificates used to validate client certificates.
                    std::list<std::string> caCertificates;
                    /// \brief
                    /// Client certificate chain.
                    std::list<std::string> certificateChain;
                    /// \brief
                    /// Client private key.
                    std::string privateKey;
                    /// \brief
                    /// Cipher list the client supports.
                    std::string cipherList;
                    /// \brief
                    /// true = Verify server certificate.
                    bool verifyServer;
                    /// \brief
                    /// Max depth of server certificate chain to verify.
                    util::ui32 maxServerCertificateChainDepth;
                    /// \brief
                    /// The OpenSSL SSL_CTX represented by this TLSContext.
                    SSL_CTXPtr ctx;

                    /// \brief
                    /// An empty TLSContext.
                    static const TLSContext Empty;

                    /// \brief
                    /// Default ctor.
                    TLSContext () :
                        loadSystemCACertificates (true),
                        verifyServer (true),
                        maxServerCertificateChainDepth (
                            DEFAULT_MAX_SERVER_CERTIFICATE_CHAIN_DEPTH) {}
                    /// \brief
                    /// ctor.
                    /// Parse the node representing a ClientSecureTCPSocket::Context.
                    /// \param[in] node pugi::xml_node representing
                    /// a ClientSecureTCPSocket::Context.
                    explicit TLSContext (const pugi::xml_node &node) :
                            loadSystemCACertificates (true),
                            verifyServer (true),
                            maxServerCertificateChainDepth (
                                DEFAULT_MAX_SERVER_CERTIFICATE_CHAIN_DEPTH) {
                        Parse (node);
                    }
                    /// \brief
                    /// Copy ctor.
                    /// \param[in] connect TLSContext to copy.
                    TLSContext (const TLSContext &context);
                    /// \brief
                    /// ctor.
                    /// \param[in] protocolVersion_ TLS protocol version.
                    /// \param[in] loadSystemCACertificates_ true = load system CA certificates.
                    /// \param[in] caCertificates_ CA certificates used to validate client certificates.
                    /// \param[in] certificateChain_ Client certificate chain.
                    /// \param[in] privateKey_ Client private key.
                    /// \param[in] cipherList_ Cipher list the client supports.
                    /// \param[in] verifyServer_ true = Verify server certificate.
                    /// \param[in] maxServerCertificateChainDepth_ Max depth of server certificate chain to verify.
                    TLSContext (
                            const std::string &protocolVersion_,
                            bool loadSystemCACertificates_,
                            const std::list<std::string> &caCertificates_,
                            const std::list<std::string> &certificateChain_,
                            const std::string &privateKey_,
                            const std::string &cipherList_,
                            bool verifyServer_ = true,
                            util::ui32 maxServerCertificateChainDepth_ = DEFAULT_MAX_SERVER_CERTIFICATE_CHAIN_DEPTH) :
                            protocolVersion (protocolVersion_),
                            loadSystemCACertificates (loadSystemCACertificates_),
                            caCertificates (caCertificates_),
                            certificateChain (certificateChain_),
                            privateKey (privateKey_),
                            cipherList (cipherList_),
                            verifyServer (verifyServer_),
                            maxServerCertificateChainDepth (maxServerCertificateChainDepth_) {
                        PrepareSSL_CTX ();
                    }

                    /// \brief
                    /// Assignment operator.
                    /// \param[in] context TLSContext to copy.
                    /// \return *this.
                    TLSContext &operator = (const TLSContext &context);

                    /// \brief
                    /// Parse the node representing a ClientSecureTCPSocket::Context.
                    /// \param[in] node pugi::xml_node representing
                    /// a ClientSecureTCPSocket::Context.
                    void Parse (const pugi::xml_node &node);
                    /// \brief
                    /// Return an XML string representing the rest
                    /// state of the ClientSecureTCPSocket.
                    /// \param[in] indentationLevel Pretty print parameter.
                    /// indents the tag with 4 * indentationLevel spaces.
                    /// \param[in] tagName Tag name (default to "Context").
                    /// \return XML string representing the rest state of the
                    /// ClientSecureTCPSocket.
                    std::string ToString (
                        std::size_t indentationLevel = 0,
                        const char *tagName = TAG_CONTEXT) const;

                    /// \brief
                    /// Construct an SSL_CTX from the values provided.
                    void PrepareSSL_CTX ();

                    /// \brief
                    /// Create an OpenSSL SSL_CTX from the values in TLSContext.
                    /// \return SSL_CTX based on the values in TLSContext.
                    SSL_CTX *GetSSL_CTX () const;

                private:
                    /// \brief
                    /// Parse a list node representing certificates.
                    /// \param[in] node List node representing certificates.
                    /// \param[out] certificate List of parsed certificates.
                    void ParseCertificates (
                        const pugi::xml_node &node,
                        std::list<std::string> &certificates);
                    /// \brief
                    /// Format an XML string containing the certificate chain.
                    /// \param[in] indentationLevel Pretty print parameter.
                    /// \param[in] certificates List of certificates to format.
                    /// \return An XML string containing the certificate chain.
                    std::string FormatCertificates (
                        std::size_t indentationLevel,
                        const std::list<std::string> &certificates) const;
                } context;
                /// \brief
                /// Extended session info.
                SessionInfo sessionInfo;

                /// \brief
                /// ctor.
                /// Parse the node representing a ClientSecureTCPSocket::Context.
                /// \param[in] node pugi::xml_node representing
                /// a ClientSecureTCPSocket::Context.
                explicit Context (const pugi::xml_node &node) :
                        Socket::Context (VALUE_CLIENT_SECURE_TCP_SOCKET, 0, 0, 0),
                        address (Address::Empty),
                        context (TLSContext::Empty),
                        sessionInfo (SessionInfo::Empty) {
                    Parse (node);
                }
                /// \brief
                /// ctor.
                /// \param[in] family Socket family specification.
                /// \param[in] type Socket type specification.
                /// \param[in] protocol Socket protocol specification.
                /// \param[in] address_ Address to connect to.
                /// \param[in] context_ TLSContext containing security parameters.
                /// \param[in] sessionInfo_ Extended session info.
                Context (
                    int family,
                    int type,
                    int protocol,
                    const Address &address_,
                    const TLSContext &context_,
                    const SessionInfo &sessionInfo_) :
                    Socket::Context (VALUE_CLIENT_SECURE_TCP_SOCKET, family, type, protocol),
                    address (address_),
                    context (context_),
                    sessionInfo (sessionInfo_) {}

                /// \brief
                /// Parse the node representing a ClientSecureTCPSocket::Context.
                /// \param[in] node pugi::xml_node representing
                /// a ClientSecureTCPSocket::Context.
                virtual void Parse (const pugi::xml_node &node);
                /// \brief
                /// Return a string representing the rest
                /// state of the ClientSecureTCPSocket.
                /// \param[in] indentationLevel Pretty print parameter.
                /// indents the tag with 4 * indentationLevel spaces.
                /// \param[in] tagName Tag name (default to "Context").
                /// \return String representing the rest state of the
                /// ClientSecureTCPSocket.
                virtual std::string ToString (
                    std::size_t indentationLevel = 0,
                    const char *tagName = TAG_CONTEXT) const;

                /// \brief
                /// Create a ClientSecureTCPSocket.
                /// \return ClientSecureTCPSocket.
                virtual Stream::SharedPtr CreateStream () const;
            };

            /// \brief
            /// Wrap an OS handle.
            /// \param[in] handle OS stream handle to wrap.
            ClientSecureTCPSocket (THEKOGANS_UTIL_HANDLE handle = THEKOGANS_UTIL_INVALID_HANDLE_VALUE) :
                SecureTCPSocket (handle) {}
            /// \brief
            /// ctor.
            /// \param[in] family Socket family specification.
            /// \param[in] type Socket type specification.
            /// \param[in] protocol Socket protocol specification.
            ClientSecureTCPSocket (
                int family,
                int type,
                int protocol) :
                SecureTCPSocket (family, type, protocol) {}

            /// \brief
            /// Streams are neither copy constructable, nor assignable.
            THEKOGANS_STREAM_DISALLOW_COPY_AND_ASSIGN (ClientSecureTCPSocket)
        };

    } // namespace stream
} // namespace thekogans

#endif // defined (THEKOGANS_STREAM_HAVE_OPENSSL)

#endif // !defined (__thekogans_stream_ClientSecureTCPSocket_h)
