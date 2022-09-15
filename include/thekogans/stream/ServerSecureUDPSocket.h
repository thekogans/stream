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

#if !defined (__thekogans_stream_ServerSecureUDPSocket_h)
#define __thekogans_stream_ServerSecureUDPSocket_h

#if defined (THEKOGANS_STREAM_HAVE_OPENSSL)

#include <memory>
#include <string>
#include <list>
#include "pugixml/pugixml.hpp"
#include "thekogans/util/Environment.h"
#include "thekogans/util/Types.h"
#include "thekogans/stream/Config.h"
#include "thekogans/stream/UDPSocket.h"
#include "thekogans/stream/SecureUDPSocket.h"
#include "thekogans/stream/OpenSSLUtils.h"

namespace thekogans {
    namespace stream {

        /// \struct ServerSecureUDPSocket ServerSecureUDPSocket.h thekogans/stream/ServerSecureUDPSocket.h
        ///
        /// \brief
        /// ServerSecureUDPSocket is used to listen for connections from (Client)SecureUDPSockets.

        struct _LIB_THEKOGANS_STREAM_DECL ServerSecureUDPSocket : public UDPSocket {
            /// \brief
            /// ServerSecureUDPSocket participates in the Stream dynamic
            /// discovery and creation.
            THEKOGANS_STREAM_DECLARE_STREAM (ServerSecureUDPSocket)

            /// \struct ServerSecureUDPSocket::Context ServerSecureUDPSocket.h
            /// thekogans/stream/ServerSecureUDPSocket.h
            ///
            /// \brief
            /// ServerSecureUDPSocket::Context represents the state of
            /// a ServerSecureUDPSocket at rest. At any time you want to
            /// reconstitute a ServerSecureUDPSocket from rest, feed a
            /// parsed (pugi::xml_node) one of:
            /// <tagName StreamType = "ServerSecureUDPSocket"
            ///          Family = ""
            ///          Type = ""
            ///          Protocol = "">
            ///     <Address Family = "inet | inet6"
            ///              Port = ""
            ///              Addr = "an inet or inet6 formated address, or host name"/>
            ///     <DTLSContext ProtocolVersion = "1.0, 1.2">
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
            ///     </DTLSContext>
            ///     <SessionInfo ServerName = "Server name to validate."
            ///                  RenegotiationFrequency = "Count of bytes before forcing the server"
            ///                                           "to renegotiate (util::UI32_MAX = never)"
            ///                  BidirectionalShutdown = "If true, perform bidirectional shutdown."
            ///                  CountTransfered = "Count of bytes transfered (read and write)."/>
            /// </tagName>
            /// to: Stream::GetContext (const pugi::xml_node &node), and it
            /// will return back to you a properly constructed and initialized
            /// ServerSecureUDPSocket::Context. Call Context::CreateStream () to
            /// recreate a ServerSecureUDPSocket from rest. Where you go with
            /// it from there is entirely up to you, but may I recommend:
            /// \see{AsyncIoEventQueue}.
            struct _LIB_THEKOGANS_STREAM_DECL Context : public Socket::Context {
                /// \brief
                /// Declare \see{RefCounted} pointers.
                THEKOGANS_UTIL_DECLARE_REF_COUNTED_POINTERS (Context)

                /// \brief
                /// "ServerSecureUDPSocket"
                static const char * const VALUE_SERVER_SECURE_UDP_SOCKET;

                /// \brief
                /// Listening address.
                Address address;
                /// \struct ServerSecureUDPSocket::Context::DTLSContext ServerSecureUDPSocket.h
                /// thekogans/stream/ServerSecureUDPSocket.h
                ///
                /// \brief
                /// DTLSContext aggregates parameters necessary to create a server side SSL_CTX.
                struct _LIB_THEKOGANS_STREAM_DECL DTLSContext {
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
                    /// "CertificateChainRSA"
                    static const char * const TAG_CERTIFICATE_CHAIN_RSA;
                    /// \brief
                    /// "CertificateChainDSA"
                    static const char * const TAG_CERTIFICATE_CHAIN_DSA;
                    /// \brief
                    /// "Certificate"
                    static const char * const TAG_CERTIFICATE;
                    /// \brief
                    /// "Encoding"
                    static const char * const ATTR_ENCODING;
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

                    enum {
                        /// \brief
                        /// Default max client certificate chain depth.
                        DEFAULT_MAX_CLIENT_CERTIFICATE_CHAIN_DEPTH = 4,
                        /// \brief
                        /// Default cached session ttl (in seconds).
                        DEFAULT_CACHED_SESSION_TTL = 300
                    };

                    /// \brief
                    /// DTLS protocol version.
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
                    /// If true, abort the connection if client did
                    /// not present a valid certificate.
                    bool requireClientCertificate;
                    /// \brief
                    /// Max depth of client certificate chain to verify.
                    util::ui32 maxClientCertificateChainDepth;
                    /// \brief
                    /// Diffie-Hellman params for ephemeral
                    /// key exchange.
                    std::string dhParams;
                    /// \brief
                    /// Elliptic curve Diffie-Hellman params
                    /// type (auto | curve | pem).
                    std::string ecdhParamsType;
                    /// \brief
                    /// Elliptic curve Diffie-Hellman params
                    /// for ephemeral key exchange.
                    std::string ecdhParams;
                    /// \brief
                    /// How long to cache the session for resumption
                    /// before declaring it invalid.
                    util::ui32 cachedSessionTTL;
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
                        requireClientCertificate (true),
                        maxClientCertificateChainDepth (
                            DEFAULT_MAX_CLIENT_CERTIFICATE_CHAIN_DEPTH),
                        cachedSessionTTL (DEFAULT_CACHED_SESSION_TTL) {}
                    /// \brief
                    /// ctor. Parse the node representing a
                    /// ServerSecureUDPSocket::Context::DtlsContext.
                    /// \param[in] node pugi::xml_node representing
                    /// a ServerSecureUDPSocket::Context::DTLSContext.
                    explicit DTLSContext (const pugi::xml_node &node) :
                            loadSystemCACertificates (true),
                            requireClientCertificate (true),
                            maxClientCertificateChainDepth (
                                DEFAULT_MAX_CLIENT_CERTIFICATE_CHAIN_DEPTH),
                            cachedSessionTTL (DEFAULT_CACHED_SESSION_TTL) {
                        Parse (node);
                    }
                    /// \brief
                    /// Copy ctor.
                    /// \param[in] connect DTLSContext to copy.
                    DTLSContext (const DTLSContext &context);

                    /// \brief
                    /// Assignment operator.
                    /// \param[in] context DTLSContext to copy.
                    /// \return *this.
                    DTLSContext &operator = (const DTLSContext &context);

                    /// \brief
                    /// Parse the node representing a
                    /// ServerSecureUDPSocket::Context::DTLSContext.
                    /// \param[in] node pugi::xml_node representing
                    /// a ServerSecureUDPSocket::Context::DTLSContext.
                    virtual void Parse (const pugi::xml_node &node);
                    /// \brief
                    /// Return a string representing the rest
                    /// state of the ServerSecureUDPSocket::Context::DTLSContext.
                    /// \param[in] indentationLevel Pretty print parameter.
                    /// indents the tag with 4 * indentationLevel spaces.
                    /// \param[in] tagName Tag name (default to "DTLSContext").
                    /// \return String representing the rest state of the
                    /// ServerSecureUDPSocket::Context::DTLSContext.
                    virtual std::string ToString (
                        std::size_t indentationLevel = 0,
                        const char *tagName = TAG_CONTEXT) const;

                    /// \brief
                    /// Construct an SSL_CTX from the values provided.
                    void PrepareSSL_CTX ();

                    /// \brief
                    /// Create an OpenSSL SSL_CTX from the values in DTLSContext.
                    /// \return SSL_CTX based on the values in DTLSContext.
                    SSL_CTX *GetSSL_CTX () const;

                private:
                    /// \brief
                    /// Helper used to parse the list of certificates.
                    /// \param[in] node Parent of Certificate children representing the list.
                    /// \param[out] certificates List of parsed certificates.
                    void ParseCertificates (
                        const pugi::xml_node &node,
                        std::list<std::string> &certificateChain);
                    /// \brief
                    /// Helper used to format a list of certificates to form a chain.
                    /// \param[in] indentationLevel Pretty print parameter.
                    /// indents the tag with 4 * indentationLevel spaces.
                    /// \param[in] certificates List of certificates to format.
                    /// \return A string representing an XML structure of a certificate chain.
                    std::string FormatCertificates (
                        std::size_t indentationLevel,
                        const std::list<std::string> &certificates) const;
                } context;
                /// \brief
                /// Extended session info.
                SessionInfo sessionInfo;

                /// \brief
                /// ctor. Parse the node representing a ServerSecureUDPSocket::Context.
                /// \param[in] node pugi::xml_node representing a ServerSecureUDPSocket::Context.
                explicit Context (const pugi::xml_node &node) :
                        Socket::Context (VALUE_SERVER_SECURE_UDP_SOCKET, 0, 0, 0),
                        address (Address::Empty),
                        context (DTLSContext::Empty),
                        sessionInfo (SessionInfo::Empty) {
                    Parse (node);
                }

                /// \brief
                /// Parse the node representing a
                /// ServerSecureUDPSocket::Context.
                /// \param[in] node pugi::xml_node representing
                /// a ServerSecureUDPSocket::Context.
                virtual void Parse (const pugi::xml_node &node);
                /// \brief
                /// Return a string representing the rest
                /// state of the ServerSecureUDPSocket.
                /// \param[in] indentationLevel Pretty print parameter.
                /// indents the tag with 4 * indentationLevel spaces.
                /// \param[in] tagName Tag name (default to "Context").
                /// \return String representing the rest state of the
                /// ServerSecureUDPSocket.
                virtual std::string ToString (
                    std::size_t indentationLevel = 0,
                    const char *tagName = TAG_CONTEXT) const;

                /// \brief
                /// Create a ServerSecureUDPSocket.
                /// \return ServerSecureUDPSocket.
                virtual Stream::SharedPtr CreateStream () const;
            };

            /// \brief
            /// Address to listen on.
            Address address;
            /// \brief
            /// DTLS context used to setup incoming connections.
            SSL_CTXPtr ctx;
            /// \brief
            /// Extended session info.
            SessionInfo sessionInfo;

            /// \brief
            /// ctor.
            /// Wrap an OS handle.
            /// \param[in] handle OS stream handle to wrap.
            ServerSecureUDPSocket (
                THEKOGANS_UTIL_HANDLE handle = THEKOGANS_UTIL_INVALID_HANDLE_VALUE) :
                UDPSocket (handle) {}
            /// \brief
            /// ctor.
            /// \param[in] family Socket family specification.
            /// \param[in] type Socket type specification.
            /// \param[in] protocol Socket protocol specification.
            ServerSecureUDPSocket (
                int family,
                int type,
                int protocol) :
                UDPSocket (family, type, protocol) {}
            /// \brief
            /// ctor.
            /// \param[in] address_ Address to listen on.
            /// \param[in] ctx_ SSL_CTX to imbue incoming connections with.
            /// \param[in] sessionInfo_ SecureUDPSocket::SessionInfo to imbue
            /// incoming connections with.
            ServerSecureUDPSocket (
                const Address &address_,
                SSL_CTX *ctx_,
                const SessionInfo &sessionInfo_);

            /// \brief
            /// Wait for connections.
            /// NOTE: This api can only be used by blocking (not async) sockets.
            /// Async sockets go in to listening mode as soon as you add them to
            /// an AsyncIoEventQueue, and return new connections through
            /// \see{AsyncIoEventSink::HandleServerSecureUDPSocketConnection}.
            /// \return The new connection.
            SecureUDPSocket::SharedPtr Accept ();

        protected:
            // Stream
            /// \brief
            /// ServerSecureUDPSocket only listens for connections.
            virtual std::size_t Read (
                    void * /*buffer*/,
                    std::size_t /*count*/) {
                assert (0);
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "%s", "ServerSecureUDPSocket can't Read.");
                return -1;
            }
            /// \brief
            /// ServerSecureUDPSocket only listens for connections.
            virtual std::size_t Write (
                    const void * /*buffer*/,
                    std::size_t /*count*/) {
                assert (0);
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "%s", "ServerSecureUDPSocket can't Write.");
                return -1;
            }
            /// \brief
            /// ServerSecureUDPSocket only listens for connections.
            virtual void WriteBuffer (
                    util::Buffer /*buffer*/) {
                assert (0);
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "%s", "ServerSecureUDPSocket can't WriteBuffer.");
            }

            // UDPSocket
            /// \brief
            /// ServerSecureUDPSocket only listens for connections.
            virtual std::size_t ReadFrom (
                    void * /*buffer*/,
                    std::size_t /*count*/,
                    Address & /*address*/) {
                assert (0);
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "%s", "ServerSecureUDPSocket can't ReadFrom.");
                return -1;
            }
            /// \brief
            /// ServerSecureUDPSocket only listens for connections.
            virtual std::size_t WriteTo (
                    const void * /*buffer*/,
                    std::size_t /*count*/,
                    const Address & /*address*/) {
                assert (0);
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "%s", "ServerSecureUDPSocket can't WriteTo.");
                return -1;
            }
            /// \brief
            /// ServerSecureUDPSocket only listens for connections.
            virtual void WriteBufferTo (
                    util::Buffer /*buffer*/,
                    const Address & /*address*/) {
                assert (0);
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "%s", "ServerSecureUDPSocket can't WriteBufferTo.");
            }

            /// \brief
            /// ServerSecureUDPSocket only listens for connections.
            virtual std::size_t ReadMsg (
                    void * /*buffer*/,
                    std::size_t /*count*/,
                    Address & /*from*/,
                    Address & /*to*/) {
                assert (0);
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "%s", "ServerSecureUDPSocket can't ReadMsg.");
                return -1;
            }
            /// \brief
            /// ServerSecureUDPSocket only listens for connections.
            virtual std::size_t WriteMsg (
                    const void *buffer,
                    std::size_t count,
                    const Address &from,
                    const Address &to) {
                assert (0);
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "%s", "ServerSecureUDPSocket can't WriteMsg.");
                return -1;
            }
            /// \brief
            /// ServerSecureUDPSocket only listens for connections.
            virtual void WriteBufferMsg (
                    util::Buffer /*buffer*/,
                    const Address & /*from*/,
                    const Address & /*to*/) {
                assert (0);
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "%s", "ServerSecureUDPSocket can't WriteBufferMsg.");
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
            /// Create a dedicated socket to act as server side connection.
            /// \param[in] from Peer address that initiated the connection.
            /// \param[in] to Local address that received the connection.
            /// \return A \see{SecureUDPSocket} representing the connection.
            SecureUDPSocket::SharedPtr CreatePeerConnection (
                util::Buffer buffer,
                const Address &from,
                const Address &to) const;

            /// \brief
            /// Streams are neither copy constructable, nor assignable.
            THEKOGANS_STREAM_DISALLOW_COPY_AND_ASSIGN (ServerSecureUDPSocket)
        };

    } // namespace stream
} // namespace thekogans

#endif // defined (THEKOGANS_STREAM_HAVE_OPENSSL)

#endif // !defined (__thekogans_stream_ServerSecureUDPSocket_h)
