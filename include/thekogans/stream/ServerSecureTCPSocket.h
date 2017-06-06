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

#if !defined (__thekogans_stream_ServerSecureTCPSocket_h)
#define __thekogans_stream_ServerSecureTCPSocket_h

#if defined (THEKOGANS_STREAM_HAVE_OPENSSL)

#include <memory>
#include <string>
#include <list>
#if defined (THEKOGANS_STREAM_HAVE_PUGIXML)
    #include <pugixml.hpp>
#endif // defined (THEKOGANS_STREAM_HAVE_PUGIXML)
#include "thekogans/util/Types.h"
#include "thekogans/stream/Config.h"
#include "thekogans/stream/TCPSocket.h"
#include "thekogans/stream/SecureTCPSocket.h"
#include "thekogans/stream/OpenSSLUtils.h"

namespace thekogans {
    namespace stream {

        /// \struct ServerSecureTCPSocket ServerSecureTCPSocket.h thekogans/stream/ServerSecureTCPSocket.h
        ///
        /// \brief
        /// ServerSecureTCPSocket is used to listen for connections from (Client)SecureTCPSockets.

        struct _LIB_THEKOGANS_STREAM_DECL ServerSecureTCPSocket : public TCPSocket {
            /// \brief
            /// ServerSecureTCPSocket participates in the Stream dynamic
            /// discovery and creation.
            THEKOGANS_STREAM_DECLARE_STREAM (ServerSecureTCPSocket)

            /// \struct ServerSecureTCPSocket::Context ServerSecureTCPSocket.h
            /// thekogans/stream/ServerSecureTCPSocket.h
            ///
            /// \brief
            /// ServerSecureTCPSocket::Context represents the state of
            /// a ServerSecureTCPSocket at rest. At any time you want to
            /// reconstitute a ServerSecureTCPSocket from rest, feed a
            /// parsed (pugi::xml_node) one of:
            /// <tagName Type = "ServerSecureTCPSocket">
            ///     <Address Family = "inet | inet6"
            ///              Port = ""
            ///              Addr = "an inet or inet6 formated address, or host name"/>
            ///     <ReuseAddress>If true call SetReuseAddress.</ReuseAddress>
            ///     <MaxPendingConnections>Max pending connection requests.</MaxPendingConnections>
            ///     <TLSContext ProtocolVersion = "1.0, 1.1, 1.2">
            ///         <LoadSystemCACertificates>
            ///             true = Load system CA certificates.
            ///         </LoadSystemCACertificates>
            ///         <CACertificates>
            ///             <Certificate>
            ///                 CA certificate.
            ///             </Certificate>
            ///             ...
            ///         </CACertificates>
            ///         <CertificateChainRSA>
            ///             <Certificate>
            ///                 Chain certificate.
            ///             </Certificate>
            ///             ...
            ///         </CertificateChainRSA>
            ///         <PrivateKeyRSA>
            ///             Private key associated with this RSA certificate.
            ///         </PrivateKeyRSA>
            ///         <CertificateChainDSA>
            ///             <Certificate>
            ///                 Chain certificate.
            ///             </Certificate>
            ///             ...
            ///         </CertificateChainDSA>
            ///         <PrivateKeyDSA>
            ///             Private key associated with this DSA certificate.
            ///         </PrivateKeyDSA>
            ///         <CipherList>':' separated cipher list.</CipherList>
            ///         <RequireClientCertificate>
            ///             If true, abort the connection if client did
            ///             not present a valid certificate.
            ///         </RequireClientCertificate>
            ///         <MaxClientCertificateChainDepth>
            ///            Max depth of client certificate chain to verify.
            ///         </MaxClientCertificateChainDepth>
            ///         <DHParams>
            ///             Optional DH params.
            ///         </DHParams>
            ///         <ECDHParams Type = "auto | curve | pem">
            ///             Optional elliptic curve DH params.
            ///         </ECDHParams>
            ///         <CachedSessionTTL>
            ///             How long to cache the session for resumption
            ///             before declaring it invalid. (0 = don't cache)
            ///         </CachedSessionTTL>
            ///     </TLSContext>
            ///     <SessionInfo ServerName = "Server name to validate."
            ///                  RenegotiationFrequency = "Count of bytes before forcing the server"
            ///                                           "to renegotiate (util::UI32_MAX = never)"
            ///                  BidirectionalShutdown = "If true, perform bidirectional shutdown."
            ///                  CountTransfered = "Count of bytes transfered (readm and write)."/>
            /// </tagName>
            /// to: Stream::GetContext (const pugi::xml_node &node), and it
            /// will return back to you a properly constructed and initialized
            /// ServerSecureTCPSocket::Context. Call Context::CreateStream () to
            /// recreate a ServerSecureTCPSocket from rest. Where you go with
            /// it from there is entirely up to you, but may I recommend:
            /// \see{AsyncIoEventQueue}.
            struct _LIB_THEKOGANS_STREAM_DECL Context : Stream::Context {
                /// \brief
                /// Convenient typedef for std::unique_ptr<Context>.
                typedef std::unique_ptr<Context> UniquePtr;

            #if defined (THEKOGANS_STREAM_HAVE_PUGIXML)
                /// \brief
                /// "ServerSecureTCPSocket"
                static const char * const VALUE_SERVER_SECURE_TCP_SOCKET;
                /// \brief
                /// "ReuseAddress"
                static const char * const TAG_REUSE_ADDRESS;
                /// \brief
                /// "MaxPendingConnections"
                static const char * const TAG_MAX_PENDING_CONNECTIONS;
            #endif // defined (THEKOGANS_STREAM_HAVE_PUGIXML)

                /// \brief
                /// Listening address.
                Address address;
                /// \brief
                /// If true, call \see{Socket::SetReuseAddress} before calling \see{Socket::Bind}.
                bool reuseAddress;
                /// \brief
                /// Max pending connection requests.
                util::i32 maxPendingConnections;
                /// \struct ServerSecureTCPSocket::Context::TLSContext ServerSecureTCPSocket.h
                /// thekogans/stream/ServerSecureTCPSocket.h
                ///
                /// \brief
                /// TLSContext aggregates parameters necessary to create a server side SSL_CTX.
                struct _LIB_THEKOGANS_STREAM_DECL TLSContext {
                #if defined (THEKOGANS_STREAM_HAVE_PUGIXML)
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
                    /// "CertificateChainRSA"
                    static const char * const TAG_CERTIFICATE_CHAIN_RSA;
                    /// \brief
                    /// "CertificateChainDSA"
                    static const char * const TAG_CERTIFICATE_CHAIN_DSA;
                    /// \brief
                    /// "Certificate"
                    static const char * const TAG_CERTIFICATE;
                    /// \brief
                    /// "PrivateKeyRSA"
                    static const char * const TAG_PRIVATE_KEY_RSA;
                    /// \brief
                    /// "PrivateKeyDSA"
                    static const char * const TAG_PRIVATE_KEY_DSA;
                    /// \brief
                    /// "CipherList"
                    static const char * const TAG_CIPHER_LIST;
                    /// \brief
                    /// "RequireClientCertificate"
                    static const char * const TAG_REQUIRE_CLIENT_CERTIFICATE;
                    /// \brief
                    /// "MaxClientCertificateChainDepth"
                    static const char * const TAG_MAX_CLIENT_CERTIFICATE_CHAIN_DEPTH;
                    /// \brief
                    /// "DHParams"
                    static const char * const TAG_DH_PARAMS;
                    /// \brief
                    /// "ECDHParams"
                    static const char * const TAG_ECDH_PARAMS;
                    /// \brief
                    /// "Type"
                    static const char * const ATTR_ECDH_PARAMS_TYPE;
                    /// \brief
                    /// "CachedSessionTTL"
                    static const char * const TAG_CACHED_SESSION_TTL;
                #endif // defined (THEKOGANS_STREAM_HAVE_PUGIXML)

                    enum {
                        /// \brief
                        /// Default max client certificate chain depth.
                        DEFAULT_MAX_CLIENT_CERTIFICATE_CHAIN_DEPTH = 4,
                        /// \brief
                        /// Default cached session ttl (in seconds).
                        DEFAULT_CACHED_SESSION_TTL = 300
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
                    /// Server RSA certificate chain.
                    std::list<std::string> certificateChainRSA;
                    /// \brief
                    /// Server RSA private key.
                    std::string privateKeyRSA;
                    /// \brief
                    /// Server DSA certificate chain.
                    std::list<std::string> certificateChainDSA;
                    /// \brief
                    /// Server DSA private key.
                    std::string privateKeyDSA;
                    /// \brief
                    /// Cipher list the server supports.
                    std::string cipherList;
                    /// \brief
                    /// true = abort the connection if client did
                    /// not present a valid certificate.
                    bool requireClientCertificate;
                    /// \brief
                    /// Max depth of client certificate chain to verify.
                    util::ui32 maxClientCertificateChainDepth;
                    /// \brief
                    /// Diffie-Hellman params for ephemeral key exchange.
                    std::string dhParams;
                    /// \brief
                    /// Elliptic curve Diffie-Hellman params type (auto | curve | pem).
                    std::string ecdhParamsType;
                    /// \brief
                    /// Elliptic curve Diffie-Hellman params for ephemeral key exchange.
                    std::string ecdhParams;
                    /// \brief
                    /// How long to cache the session for resumption
                    /// before declaring it invalid.
                    util::ui32 cachedSessionTTL;
                    /// \brief
                    /// The OpenSSL SSL_CTX represented by this TLSContext.
                    SSL_CTXPtr ctx;

                    /// \brief
                    /// An empty TLSContext.
                    static TLSContext Empty;

                    /// \brief
                    /// Default ctor.
                    TLSContext () :
                        loadSystemCACertificates (true),
                        requireClientCertificate (true),
                        maxClientCertificateChainDepth (
                            DEFAULT_MAX_CLIENT_CERTIFICATE_CHAIN_DEPTH),
                        cachedSessionTTL (DEFAULT_CACHED_SESSION_TTL) {}
                #if defined (THEKOGANS_STREAM_HAVE_PUGIXML)
                    /// \brief
                    /// ctor. Parse the node representing a
                    /// ServerSecureTCPSocket::Context::TlSContext.
                    /// \param[in] node pugi::xml_node representing
                    /// a ServerSecureTCPSocket::Context::TLSContext.
                    explicit TLSContext (const pugi::xml_node &node) :
                            loadSystemCACertificates (true),
                            requireClientCertificate (true),
                            maxClientCertificateChainDepth (
                                DEFAULT_MAX_CLIENT_CERTIFICATE_CHAIN_DEPTH),
                            cachedSessionTTL (DEFAULT_CACHED_SESSION_TTL) {
                        Parse (node);
                    }
                #endif // defined (THEKOGANS_STREAM_HAVE_PUGIXML)
                    /// \brief
                    /// Copy ctor.
                    /// \param[in] connect TLSContext to copy.
                    TLSContext (const TLSContext &context);
                    /// \brief
                    /// ctor.
                    /// \param[in] protocolVersion_ TLS protocol version.
                    /// \param[in] loadSystemCACertificates_ true = load system CA certificates.
                    /// \param[in] caCertificate_ CA certificate used to validate client certificates.
                    /// \param[in] certificateChainRSA_ Server RSA certificate chain.
                    /// \param[in] privateKeyRSA_ Server RSA private key.
                    /// \param[in] certificateChainDSA_ Server DSA certificate chain.
                    /// \param[in] privateKeyDSA_ Server DSA private key.
                    /// \param[in] cipherList_ Cipher list the server supports.
                    /// \param[in] requireClientCertificate_ true = abort the connection if client did
                    /// not present a valid certificate.
                    /// \param[in] maxClientCertificateChainDepth_ Max depth of client certificate chain to verify.
                    /// \param[in] dhParams_ Diffie-Hellman params for ephemeral key exchange.
                    /// \param[in] ecdhParamsType_ Elliptic curve Diffie-Hellman params type (auto | curve | pem).
                    /// \param[in] ecdhParams_ Elliptic curve Diffie-Hellman params for ephemeral key exchange.
                    /// \param[in] cachedSessionTTL_ How long to cache the session for resumption
                    /// before declaring it invalid.
                    TLSContext (
                        const std::string &protocolVersion_,
                        bool loadSystemCACertificates_,
                        const std::list<std::string> &caCertificates_,
                        const std::list<std::string> &certificateChainRSA_,
                        const std::string &privateKeyRSA_,
                        const std::list<std::string> &certificateChainDSA_,
                        const std::string &privateKeyDSA_,
                        const std::string &cipherList_,
                        bool requireClientCertificate_,
                        util::ui32 maxClientCertificateChainDepth_,
                        const std::string &dhParams_,
                        const std::string &ecdhParamsType_,
                        const std::string &ecdhParams_,
                        util::ui32 cachedSessionTTL_) :
                        protocolVersion (protocolVersion_),
                        loadSystemCACertificates (loadSystemCACertificates_),
                        caCertificates (caCertificates_),
                        certificateChainRSA (certificateChainRSA_),
                        privateKeyRSA (privateKeyRSA_),
                        certificateChainDSA (certificateChainDSA_),
                        privateKeyDSA (privateKeyDSA_),
                        cipherList (cipherList_),
                        requireClientCertificate (requireClientCertificate_),
                        maxClientCertificateChainDepth (maxClientCertificateChainDepth_),
                        dhParams (dhParams_),
                        ecdhParamsType (ecdhParamsType_),
                        ecdhParams (ecdhParams_),
                        cachedSessionTTL (cachedSessionTTL_) {}

                    /// \brief
                    /// Assignment operator.
                    /// \param[in] context TLSContext to copy.
                    /// \return *this.
                    TLSContext &operator = (const TLSContext &context);

                #if defined (THEKOGANS_STREAM_HAVE_PUGIXML)
                    /// \brief
                    /// Parse the node representing a
                    /// ServerSecureTCPSocket::Context::TLSContext.
                    /// \param[in] node pugi::xml_node representing
                    /// a ServerSecureTCPSocket::Context::TLSContext.
                    virtual void Parse (const pugi::xml_node &node);
                    /// \brief
                    /// Return a string representing the rest
                    /// state of the ServerSecureTCPSocket::Context::TLSContext.
                    /// \param[in] indentationLevel Pretty print parameter.
                    /// indents the tag with 4 * indentationLevel spaces.
                    /// \param[in] tagName Tag name (default to "TLSContext").
                    /// \return String representing the rest state of the
                    /// ServerSecureTCPSocket::Context::TLSContext.
                    virtual std::string ToString (
                        util::ui32 indentationLevel = 0,
                        const char *tagName = TAG_CONTEXT) const;
                #endif // defined (THEKOGANS_STREAM_HAVE_PUGIXML)

                    void PrepareSSL_CTX ();

                    /// \brief
                    /// Create an OpenSSL SSL_CTX from the values in TLSContext.
                    /// \return SSL_CTX based on the values in TLSContext.
                    SSL_CTX *GetSSL_CTX () const;

                #if defined (THEKOGANS_STREAM_HAVE_PUGIXML)
                private:
                    /// \brief
                    /// Helper used to parse the certificate list.
                    /// \param[in] node Parent of Certificate children representing the list.
                    /// \param[out] certificates List of parsed certificates.
                    void ParseCertificates (
                        const pugi::xml_node &node,
                        std::list<std::string> &certificates);
                    /// \brief
                    /// Helper used to format a list of certificates to form a chain.
                    /// \param[in] indentationLevel Pretty print parameter.
                    /// indents the tag with 4 * indentationLevel spaces.
                    /// \param[in] certificates List of certificates to format.
                    /// \return A string representing an XML structure of a certificate chain.
                    std::string FormatCertificates (
                        util::ui32 indentationLevel,
                        const std::list<std::string> &certificates) const;
                #endif // defined (THEKOGANS_STREAM_HAVE_PUGIXML)
                } context;
                /// \brief
                /// Extended session info.
                SessionInfo sessionInfo;

                /// \brief
                /// ctor. Parse the node representing a
                /// ServerSecureTCPSocket::Context.
                /// \param[in] node pugi::xml_node representing
                /// a ServerSecureTCPSocket::Context.
                Context (
                    const Address &address_ = Address::Empty,
                    bool reuseAddress_ = false,
                    util::ui32 maxPendingConnections_ = TCPSocket::DEFAULT_MAX_PENDING_CONNECTIONS,
                    const TLSContext &context_ = TLSContext::Empty,
                    const SessionInfo &sessionInfo_ = SessionInfo::Empty) :
                    address (address_),
                    reuseAddress (reuseAddress_),
                    maxPendingConnections (maxPendingConnections_),
                    context (context_),
                    sessionInfo (sessionInfo_) {}
            #if defined (THEKOGANS_STREAM_HAVE_PUGIXML)
                /// \brief
                /// ctor. Parse the node representing a
                /// ServerSecureTCPSocket::Context.
                /// \param[in] node pugi::xml_node representing
                /// a ServerSecureTCPSocket::Context.
                explicit Context (const pugi::xml_node &node) :
                        Stream::Context (VALUE_SERVER_SECURE_TCP_SOCKET),
                        address (Address::Empty),
                        reuseAddress (false),
                        maxPendingConnections (TCPSocket::DEFAULT_MAX_PENDING_CONNECTIONS),
                        context (TLSContext::Empty),
                        sessionInfo (SessionInfo::Empty) {
                    Parse (node);
                }

                /// \brief
                /// Parse the node representing a
                /// ServerSecureTCPSocket::Context.
                /// \param[in] node pugi::xml_node representing
                /// a ServerSecureTCPSocket::Context.
                virtual void Parse (const pugi::xml_node &node);
                /// \brief
                /// Return a string representing the rest
                /// state of the ServerSecureTCPSocket.
                /// \param[in] indentationLevel Pretty print parameter.
                /// indents the tag with 4 * indentationLevel spaces.
                /// \param[in] tagName Tag name (default to "Context").
                /// \return String representing the rest state of the
                /// ServerSecureTCPSocket.
                virtual std::string ToString (
                    util::ui32 indentationLevel = 0,
                    const char *tagName = TAG_CONTEXT) const;
            #endif // defined (THEKOGANS_STREAM_HAVE_PUGIXML)

                /// \brief
                /// Create a ServerSecureTCPSocket.
                /// \return ServerSecureTCPSocket.
                virtual Stream::Ptr CreateStream () const;
            };

            /// \brief
            /// TLS context used to setup incoming connections.
            SSL_CTXPtr ctx;
            /// \brief
            /// Extended session info.
            SessionInfo sessionInfo;

            /// \brief
            /// ctor.
            /// Wrap an OS handle.
            /// \param[in] handle_ OS stream handle to wrap.
            ServerSecureTCPSocket (THEKOGANS_UTIL_HANDLE handle = THEKOGANS_UTIL_INVALID_HANDLE_VALUE) :
                TCPSocket (handle) {}
            /// \brief
            /// ctor.
            /// \param[in] family Socket family specification.
            /// \param[in] type Socket type specification.
            /// \param[in] protocol Socket protocol specification.
            ServerSecureTCPSocket (
                int family,
                int type,
                int protocol) :
                TCPSocket (family, type, protocol) {}
            /// \brief
            /// ctor.
            /// \param[in] address Address to listen on.
            /// \param[in] reuseAddress Call \see{Socket::SetReuseAddress} with this parameter.
            /// \param[in] maxPendingConnections Max pending connection requests.
            /// \param[in] ctx_ SSL_CTX to imbue incoming connections with.
            /// \param[in] sessionInfo_ \see{SecureTCPSocket::SessionInfo}
            /// to imbue incoming connections with.
            ServerSecureTCPSocket (
                const Address &address,
                bool reuseAddress,
                util::ui32 maxPendingConnections,
                SSL_CTX *ctx_,
                const SessionInfo &sessionInfo_);

            /// \brief
            /// Wait for connections.
            /// NOTE: This api can only be used by blocking (not async) sockets.
            /// Async sockets go in to listening mode as soon as you add them to
            /// an \see{AsyncIoEventQueue}, and return new connections through
            /// \see{AsyncIoEventSink::HandleServerSecureTCPSocketConnection}.
            /// \return The new connection.
            SecureTCPSocket::Ptr Accept ();

        protected:
            // Stream
            /// \brief
            /// ServerSecureTCPSocket only listens for connections.
            virtual util::ui32 Read (
                    void * /*buffer*/,
                    util::ui32 /*count*/) {
                assert (0);
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "%s", "ServerSecureTCPSocket can't Read.");
                return -1;
            }
            /// \brief
            /// ServerSecureTCPSocket only listens for connections.
            virtual util::ui32 Write (
                    const void * /*buffer*/,
                    util::ui32 /*count*/) {
                assert (0);
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "%s", "ServerSecureTCPSocket can't Write.");
                return -1;
            }
            /// \brief
            /// ServerSecureTCPSocket only listens for connections.
            virtual void WriteBuffer (
                    util::Buffer::UniquePtr /*buffer*/) {
                assert (0);
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "%s", "ServerSecureTCPSocket can't WriteBuffer.");
            }

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
            /// Streams are neither copy constructable, nor assignable.
            THEKOGANS_STREAM_DISALLOW_COPY_AND_ASSIGN (ServerSecureTCPSocket)
        };

    } // namespace stream
} // namespace thekogans

#endif // defined (THEKOGANS_STREAM_HAVE_OPENSSL)

#endif // !defined (__thekogans_stream_ServerSecureTCPSocket_h)
