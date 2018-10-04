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

#if !defined (__thekogans_stream_ClientSecureUDPSocket_h)
#define __thekogans_stream_ClientSecureUDPSocket_h

#if defined (THEKOGANS_STREAM_HAVE_OPENSSL)

#include <string>
#include <list>
#if defined (THEKOGANS_STREAM_HAVE_PUGIXML)
    #include <pugixml.hpp>
#endif // defined (THEKOGANS_STREAM_HAVE_PUGIXML)
#include "thekogans/util/Types.h"
#include "thekogans/stream/Config.h"
#include "thekogans/stream/SecureUDPSocket.h"
#include "thekogans/stream/OpenSSLUtils.h"

namespace thekogans {
    namespace stream {

        /// \struct ClientSecureUDPSocket ClientSecureUDPSocket.h thekogans/stream/ClientSecureUDPSocket.h
        ///
        /// \brief
        /// ClientSecureUDPSocket's sole reason for being is to expose ClientSecureUDPSocket::Context.
        /// All the heavy lifting is done by \see{SecureUDPSocket}.

        struct _LIB_THEKOGANS_STREAM_DECL ClientSecureUDPSocket : public SecureUDPSocket {
            /// \brief
            /// ClientSecureUDPSocket participates in the Stream dynamic
            /// discovery and creation.
            THEKOGANS_STREAM_DECLARE_STREAM (ClientSecureUDPSocket)

            /// \struct ClientSecureUDPSocket::Context ClientSecureUDPSocket.h
            /// thekogans/stream/ClientSecureUDPSocket.h
            ///
            /// \brief
            /// ClientSecureUDPSocket::Context represents the state
            /// of a ClientSecureUDPSocket at rest. At any time you want
            /// to reconstitute a ClientSecureUDPSocket from rest,
            /// feed a parsed (pugi::xml_node) one of:
            /// <tagName Type = "ClientSecureUDPSocket">
            ///     <Address Family = "inet | inet6"
            ///              Port = ""
            ///              Addr = "an inet or inet6 formated address, or host name"/>
            ///     <DTLSContext ProtocolVersion = "1.0, 1.2...">
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
            ///         <PrivateKey>
            ///             Private key associated with this certificate.
            ///         </PrivateKey>
            ///         <CipherList>':' separated cipher list.</CipherList>
            ///         <VerifyServer>
            ///             true = Verify server certificate.
            ///         </VerifyServer>
            ///         <MaxServerCertificateChainDepth>
            ///             Max depth of server certificate chain to verify.
            ///         </MaxServerCertificateChainDepth>
            ///     </DTLSContext>
            ///     <SessionInfo ServerName = "Server name to validate."
            ///                  RenegotiationFrequency = "Count of bytes before forcing the server"
            ///                                           "to renegotiate (util::UI32_MAX = never)"
            ///                  BidirectionalShutdown = "If true, perform bidirectional shutdown."
            ///                  CountTransfered = "Count of bytes transfered (read and write)."/>
            /// </tagName>
            /// to: Stream::GetContext (const pugi::xml_node &node), and it
            /// will return back to you a properly constructed and initialized
            /// ClientSecureUDPSocket::Context. Call Context::CreateStream () to
            /// recreate a ClientSecureUDPSocket from rest. Where you go with
            /// it from there is entirely up to you, but may I recommend:
            /// \see{AsyncIoEventQueue}.
            struct _LIB_THEKOGANS_STREAM_DECL Context : Stream::Context {
                /// \brief
                /// Convenient typedef for std::unique_ptr<Context>.
                typedef std::unique_ptr<Context> UniquePtr;

            #if defined (THEKOGANS_STREAM_HAVE_PUGIXML)
                /// \brief
                /// "ClientSecureUDPSocket".
                static const char * const VALUE_CLIENT_SECURE_UDP_SOCKET;
            #endif // defined (THEKOGANS_STREAM_HAVE_PUGIXML)

                /// \brief
                /// Address to connect to.
                Address address;
                /// \struct ClientSecureUDPSocket::Context::DTLSContext ClientSecureUDPSocket.h
                /// thekogans/stream/ClientSecureUDPSocket.h
                ///
                /// \brief
                /// DTLSContext aggregates parameters necessary to create a client side SSL_CTX.
                struct _LIB_THEKOGANS_STREAM_DECL DTLSContext {
                #if defined (THEKOGANS_STREAM_HAVE_PUGIXML)
                    /// \brief
                    /// "DTLSContext"
                    static const char * const TAG_DTLS_CONTEXT;
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
                    /// "CipherList"
                    static const char * const TAG_CIPHER_LIST;
                    /// \brief
                    /// "VerifyServer"
                    static const char * const TAG_VERIFY_SERVER;
                    /// \brief
                    /// "MaxServerCertificateChainDepth"
                    static const char * const TAG_MAX_SERVER_CERTIFICATE_CHAIN_DEPTH;
                #endif // defined (THEKOGANS_STREAM_HAVE_PUGIXML)

                    enum {
                        /// \brief
                        /// Default max server certificate chain depth.
                        DEFAULT_MAX_SERVER_CERTIFICATE_CHAIN_DEPTH = 4,
                    };

                    /// \brief
                    /// DTLS protocol version.
                    std::string protocolVersion;
                    /// \brief
                    /// true = Load system CA certificates.
                    bool loadSystemCACertificates;
                    /// \brief
                    /// Convenient typedef for std::list<std::string>.
                    typedef std::list<std::string> Certificates;
                    /// \brief
                    /// CA certificates used to validate client certificates.
                    Certificates caCertificates;
                    /// \brief
                    /// Server certificate chain file.
                    Certificates certificateChain;
                    /// \brief
                    /// Server private key file.
                    std::string privateKey;
                    /// \brief
                    /// Cipher list the server supports.
                    std::string cipherList;
                    /// \brief
                    /// true = Verify server certificate.
                    bool verifyServer;
                    /// \brief
                    /// Max depth of server certificate chain to verify.
                    util::ui32 maxServerCertificateChainDepth;
                    /// \brief
                    /// The OpenSSL SSL_CTX represented by this DTLSContext.
                    SSL_CTXPtr ctx;

                    /// \brief
                    /// An empty DTLSContext.
                    static const DTLSContext Empty;

                    /// \brief
                    /// Default ctor.
                    DTLSContext () :
                        loadSystemCACertificates (true),
                        verifyServer (true),
                        maxServerCertificateChainDepth (
                            DEFAULT_MAX_SERVER_CERTIFICATE_CHAIN_DEPTH) {}
                #if defined (THEKOGANS_STREAM_HAVE_PUGIXML)
                    /// \brief
                    /// ctor.
                    /// Parse the node representing a ClientSecureUDPSocket::Context.
                    /// \param[in] node pugi::xml_node representing
                    /// a ClientSecureUDPSocket::Context.
                    explicit DTLSContext (const pugi::xml_node &node) :
                            loadSystemCACertificates (true),
                            verifyServer (true),
                            maxServerCertificateChainDepth (
                                DEFAULT_MAX_SERVER_CERTIFICATE_CHAIN_DEPTH) {
                        Parse (node);
                    }
                #endif // defined (THEKOGANS_STREAM_HAVE_PUGIXML)
                    /// \brief
                    /// Copy ctor.
                    /// \param[in] connect DTLSContext to copy.
                    DTLSContext (const DTLSContext &context);
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
                    DTLSContext (
                            const std::string &protocolVersion_,
                            bool loadSystemCACertificates_,
                            const Certificates &caCertificates_,
                            const Certificates &certificateChain_,
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
                    /// \param[in] context DTLSContext to copy.
                    /// \return *this.
                    DTLSContext &operator = (const DTLSContext &context);

                #if defined (THEKOGANS_STREAM_HAVE_PUGIXML)
                    /// \brief
                    /// Parse the node representing a ClientSecureUDPSocket::Context.
                    /// \param[in] node pugi::xml_node representing
                    /// a ClientSecureUDPSocket::Context.
                    void Parse (const pugi::xml_node &node);
                    /// \brief
                    /// Return an XML string representing the rest
                    /// state of the ClientSecureUDPSocket.
                    /// \param[in] indentationLevel Pretty print parameter.
                    /// indents the tag with 4 * indentationLevel spaces.
                    /// \param[in] tagName Tag name (default to "Context").
                    /// \return XML string representing the rest state of the
                    /// ClientSecureUDPSocket.
                    std::string ToString (
                        std::size_t indentationLevel = 0,
                        const char *tagName = TAG_CONTEXT) const;
                #endif // defined (THEKOGANS_STREAM_HAVE_PUGIXML)

                    /// \brief
                    /// Construct an SSL_CTX from the values provided.
                    void PrepareSSL_CTX ();

                    /// \brief
                    /// Create an OpenSSL SSL_CTX from the values in DTLSContext.
                    /// \return SSL_CTX based on the values in DTLSContext.
                    SSL_CTX *GetSSL_CTX () const;

                #if defined (THEKOGANS_STREAM_HAVE_PUGIXML)
                private:
                    /// \brief
                    /// Parse a list node representing the certificate chain.
                    /// \param[in] node List node representing the certificate chain.
                    /// \param[out] certificates List of parsed certificates.
                    void ParseCertificates (
                        const pugi::xml_node &node,
                        Certificates &certificates);
                    /// \brief
                    /// Format an XML string containing the certificate chain.
                    /// \param[in] indentationLevel Pretty print parameter.
                    /// \param[in] certificates List of certificates to format.
                    /// \return An XML string containing the certificate chain.
                    std::string FormatCertificates (
                        std::size_t indentationLevel,
                        const Certificates &certificates) const;
                #endif // defined (THEKOGANS_STREAM_HAVE_PUGIXML)
                } context;
                /// \brief
                /// Extended session info.
                SessionInfo sessionInfo;

            #if defined (THEKOGANS_STREAM_HAVE_PUGIXML)
                /// \brief
                /// ctor.
                /// Parse the node representing a ClientSecureUDPSocket::Context.
                /// \param[in] node pugi::xml_node representing
                /// a ClientSecureUDPSocket::Context.
                explicit Context (const pugi::xml_node &node) :
                        Stream::Context (VALUE_CLIENT_SECURE_UDP_SOCKET),
                        address (Address::Empty),
                        context (DTLSContext::Empty),
                        sessionInfo (SessionInfo::Empty) {
                    Parse (node);
                }

                /// \brief
                /// Parse the node representing a ClientSecureUDPSocket::Context.
                /// \param[in] node pugi::xml_node representing
                /// a ClientSecureUDPSocket::Context.
                virtual void Parse (const pugi::xml_node &node);
                /// \brief
                /// Return a string representing the rest
                /// state of the ClientSecureUDPSocket.
                /// \param[in] indentationLevel Pretty print parameter.
                /// indents the tag with 4 * indentationLevel spaces.
                /// \param[in] tagName Tag name (default to "Context").
                /// \return String representing the rest state of the
                /// ClientSecureUDPSocket.
                virtual std::string ToString (
                    std::size_t indentationLevel = 0,
                    const char *tagName = TAG_CONTEXT) const;
            #endif // defined (THEKOGANS_STREAM_HAVE_PUGIXML)

                /// \brief
                /// Create a ClientSecureUDPSocket.
                /// \return ClientSecureUDPSocket.
                virtual Stream::Ptr CreateStream () const;
            };

            /// \brief
            /// Wrap an OS handle.
            /// \param[in] handle OS stream handle to wrap.
            ClientSecureUDPSocket (THEKOGANS_UTIL_HANDLE handle = THEKOGANS_UTIL_INVALID_HANDLE_VALUE) :
                SecureUDPSocket (handle) {}
            /// \brief
            /// ctor.
            /// \param[in] family Socket family specification.
            /// \param[in] type Socket type specification.
            /// \param[in] protocol Socket protocol specification.
            ClientSecureUDPSocket (
                int family,
                int type,
                int protocol) :
                SecureUDPSocket (family, type, protocol) {}

            /// \brief
            /// Streams are neither copy constructable, nor assignable.
            THEKOGANS_STREAM_DISALLOW_COPY_AND_ASSIGN (ClientSecureUDPSocket)
        };

    } // namespace stream
} // namespace thekogans

#endif // defined (THEKOGANS_STREAM_HAVE_OPENSSL)

#endif // !defined (__thekogans_stream_ClientSecureUDPSocket_h)
