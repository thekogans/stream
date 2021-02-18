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

#if !defined (__thekogans_stream_ServerUDPSocket_h)
#define __thekogans_stream_ServerUDPSocket_h

#include <memory>
#include <string>
#include "pugixml/pugixml.hpp"
#include "thekogans/util/Types.h"
#include "thekogans/stream/Config.h"
#include "thekogans/stream/UDPSocket.h"

namespace thekogans {
    namespace stream {

        /// \struct ServerUDPSocket ServerUDPSocket.h thekogans/stream/ServerUDPSocket.h
        ///
        /// \brief
        /// ServerUDPSocket is used to listen for connections from (Client)UDPSockets.
        /// Since UDP is connectionless, ServerUDPSocket creates a new 'connection' by
        /// creating a new UDPSocket and returning it along with the data-gram. The new
        /// UDPSocket is initialized to be bound and connected to the addresses returned
        /// by ReadMsg. All subsequent communications through the socket should be
        /// performed using Read/Write.
        /// NOTE: Since UDP has no concept of disconnect, there are two possible ways
        /// to detect client shutdown. 1. Build disconnect in to your protocol. 2. Set
        /// a timeout on the new UDPSocket. Please see serverudpecho example.

        struct _LIB_THEKOGANS_STREAM_DECL ServerUDPSocket : public UDPSocket {
            /// \brief
            /// ServerUDPSocket participates in the Stream dynamic
            /// discovery and creation.
            THEKOGANS_STREAM_DECLARE_STREAM (ServerUDPSocket)

            /// \struct ServerUDPSocket::Context UDPSocket.h thekogans/stream/ServerUDPSocket.h
            ///
            /// \brief
            /// ServerUDPSocket::Context represents the state
            /// of a ServerUDPSocket at rest. At any time you want
            /// to reconstitute a ServerUDPSocket from rest,
            /// feed a parsed (pugi::xml_node) one of:
            /// <tagName StreamType = "ServerUDPSocket"
            ///          Family = "inet | inet6 | local"
            ///          Type = "dgram"
            ///          Protocol = "udp">
            ///     <Address Family = "inet | inet6"
            ///              Port = ""
            ///              Addr = "an inet or inet6 formated address, or host name"/>
            ///     or
            ///     <Address Family = "local"
            ///              Path = ""/>
            ///     <MaxMessageLength>Maximum length of initiating message.</MaxMessageLength>
            /// </tagName>
            /// to: Stream::GetContext (const pugi::xml_node &node), and it
            /// will return back to you a properly constructed and initialized
            /// ServerUDPSocket::Context. Call Context::CreateStream () to recreate a
            /// ServerUDPSocket from rest. Where you go with it from there is entirely
            /// up to you, but may I recommend: \see{AsyncIoEventQueue}.
            struct _LIB_THEKOGANS_STREAM_DECL Context : public Socket::Context {
                /// \brief
                /// Declare \see{RefCounted} pointers.
                THEKOGANS_UTIL_DECLARE_REF_COUNTED_POINTERS (Context)

                /// \brief
                /// "ServerUDPSocket"
                static const char * const VALUE_SERVER_UDP_SOCKET;
                /// \brief
                /// "MaxMessageLength"
                static const char * const TAG_MAX_MESSAGE_LENGTH;

                /// \brief
                /// Address to listen on.
                Address address;
                /// \brief
                /// Maximum length of initiating message.
                /// NOTE: This is not the length of the receive buffer.
                /// This is the maximum length of the first message sent
                /// by a client. If you want to be able to handle multiple
                /// clients 'connecting' at once, you will need to set the
                /// receive buffer to some multiple of this value.
                std::size_t maxMessageLength;

                /// \brief
                /// ctor. Parse the node representing a
                /// UDPSocket::Context.
                /// \param[in] node pugi::xml_node representing
                /// a UDPSocket::Context.
                explicit Context (const pugi::xml_node &node) :
                        Socket::Context (VALUE_SERVER_UDP_SOCKET, 0, 0, 0),
                        address (Address::Empty),
                        maxMessageLength (0) {
                    Parse (node);
                }
                /// \brief
                /// ctor.
                /// \param[in] family Socket family specification.
                /// \param[in] type Socket type specification.
                /// \param[in] protocol Socket protocol specification.
                /// \param[in] address_ Address to listen on.
                /// \param[in] maxMessageLength_ Maximum length of initiating message.
                Context (
                    int family,
                    int type,
                    int protocol,
                    const Address &address_,
                    std::size_t maxMessageLength_) :
                    Socket::Context (VALUE_SERVER_UDP_SOCKET, family, type, protocol),
                    address (address_),
                    maxMessageLength (maxMessageLength_) {}

                /// \brief
                /// Parse the node representing a
                /// UDPSocket::Context.
                /// \param[in] node pugi::xml_node representing
                /// a UDPSocket::Context.
                virtual void Parse (const pugi::xml_node &node);
                /// \brief
                /// Return a string representing the rest
                /// state of the UDPSocket.
                /// \param[in] indentationLevel Pretty print parameter.
                /// indents the tag with 4 * indentationLevel spaces.
                /// \param[in] tagName Tag name (default to "Context").
                /// \return String representing the rest state of the
                /// UDPSocket.
                virtual std::string ToString (
                    std::size_t indentationLevel = 0,
                    const char *tagName = TAG_CONTEXT) const;

                /// \brief
                /// Create a UDPSocket based on the address.
                /// \return UDPSocket based on the address.
                virtual Stream::SharedPtr CreateStream () const;
            };

            /// \brief
            /// Maximum length of initiating message.
            /// NOTE: This is not the length of the receive buffer.
            /// This is the maximum length of the first message sent
            /// by a client. If you want to be able to handle multiple
            /// clients 'connecting' at once, you will need to set the
            /// receive buffer to some multiple of this value.
            const std::size_t maxMessageLength;

            enum {
                /// \brief
                /// Default maximum message length.
                DEFAULT_MAX_MESSAGE_LENGTH = 16384
            };

            /// \brief
            /// ctor.
            /// Wrap an OS handle.
            /// \param[in] handle OS stream handle to wrap.
            /// \param[in] maxMessageLength_ Maximum length of initiating message.
            ServerUDPSocket (
                THEKOGANS_UTIL_HANDLE handle = THEKOGANS_UTIL_INVALID_HANDLE_VALUE,
                std::size_t maxMessageLength_ = DEFAULT_MAX_MESSAGE_LENGTH) :
                UDPSocket (handle),
                maxMessageLength (maxMessageLength_) {}
            /// \brief
            /// ctor.
            /// \param[in] family Socket family specification.
            /// \param[in] type Socket type specification.
            /// \param[in] protocol Socket protocol specification.
            /// \param[in] maxMessageLength_ Maximum length of initiating message.
            ServerUDPSocket (
                int family,
                int type,
                int protocol,
                std::size_t maxMessageLength_ = DEFAULT_MAX_MESSAGE_LENGTH) :
                UDPSocket (family, type, protocol),
                maxMessageLength (maxMessageLength_) {}
            /// \brief
            /// ctor.
            /// \param[in] address Address to listen on.
            /// \param[in] maxMessageLength_ Maximum length of initiating message.
            ServerUDPSocket (
                const Address &address,
                std::size_t maxMessageLength_ = DEFAULT_MAX_MESSAGE_LENGTH);

            /// \struct Connection ServerUDPSocket.h thekogans/stream/ServerUDPSocket.h
            ///
            /// \brief
            /// Connection encapsulates the new connection data. Since ServerUDPSocket
            /// has no idea what you're planning to do with the first dgram, it sends
            /// it along with the new socket.
            struct _LIB_THEKOGANS_STREAM_DECL Connection : public util::RefCounted {
                /// \brief
                /// Declare \see{RefCounted} pointers.
                THEKOGANS_UTIL_DECLARE_REF_COUNTED_POINTERS (Connection)

                /// \brief
                /// Connection has a private heap to help with memory
                /// management, performance, and global heap fragmentation.
                THEKOGANS_UTIL_DECLARE_HEAP_WITH_LOCK (Connection, util::SpinLock)

                /// \brief
                /// The new connection.
                UDPSocket::SharedPtr udpSocket;
                /// \brief
                /// The datagram that arrived.
                util::Buffer buffer;

                /// \brief
                /// ctor.
                /// \param[in] buffer_ The datagram that arrived.
                /// \param[in] from The address of the host that sent the message.
                /// \param[in] to The local interface address that received the message.
                /// \param[in] maxMessageLength Maximum message length.
                Connection (
                        util::Buffer buffer_,
                        const Address &from,
                        const Address &to,
                        std::size_t maxMessageLength) :
                        udpSocket (new UDPSocket (from.GetFamily (), SOCK_DGRAM, IPPROTO_UDP)),
                        buffer (std::move (buffer_)) {
                    udpSocket->SetReuseAddress (true);
                #if defined (SO_REUSEPORT) || defined (SO_REUSE_UNICASTPORT)
                    udpSocket->SetReusePort (true);
                #endif // defined (SO_REUSEPORT) || defined (SO_REUSE_UNICASTPORT)
                    udpSocket->Bind (to);
                    udpSocket->Connect (from);
                    udpSocket->SetReceiveBufferSize (maxMessageLength);
                    udpSocket->SetSendBufferSize (maxMessageLength);
                }
            };

            /// \brief
            /// Wait for connections.
            /// NOTE: This api can only be used by blocking (not async) sockets.
            /// Async sockets go in to listening mode as soon as you add them to
            /// an AsyncIoEventQueue, and return new connections through
            /// \see{AsyncIoEventSink::HandleServerUDPSocketConnection}.
            /// \return The new connection info.
            Connection::SharedPtr Accept ();

        protected:
            // Stream
            /// \brief
            /// ServerUDPSocket only listens for connections.
            virtual std::size_t Read (
                    void * /*buffer*/,
                    std::size_t /*count*/) {
                assert (0);
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "%s", "ServerUDPSocket can't Read.");
                return -1;
            }
            /// \brief
            /// ServerUDPSocket only listens for connections.
            virtual std::size_t Write (
                    const void * /*buffer*/,
                    std::size_t /*count*/) {
                assert (0);
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "%s", "ServerUDPSocket can't Write.");
                return -1;
            }
            /// \brief
            /// ServerUDPSocket only listens for connections.
            virtual void WriteBuffer (
                    util::Buffer /*buffer*/) {
                assert (0);
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "%s", "ServerUDPSocket can't WriteBuffer.");
            }

            // UDPSocket
            /// \brief
            /// ServerUDPSocket only listens for connections.
            virtual std::size_t ReadFrom (
                    void *buffer,
                    std::size_t count,
                    Address &address) {
                assert (0);
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "%s", "ServerUDPSocket can't ReadFrom.");
                return -1;
            }
            /// \brief
            /// ServerUDPSocket only listens for connections.
            virtual std::size_t WriteTo (
                    const void *buffer,
                    std::size_t count,
                    const Address &address) {
                assert (0);
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "%s", "ServerUDPSocket can't WriteTo.");
                return -1;
            }
            /// \brief
            /// ServerUDPSocket only listens for connections.
            virtual void WriteBufferTo (
                    util::Buffer buffer,
                    const Address &address) {
                assert (0);
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "%s", "ServerUDPSocket can't WriteBufferTo.");
            }

            /// \brief
            /// ServerUDPSocket only listens for connections.
            virtual std::size_t ReadMsg (
                    void *buffer,
                    std::size_t count,
                    Address &from,
                    Address &to) {
                assert (0);
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "%s", "ServerUDPSocket can't ReadMsg.");
                return -1;
            }
            /// \brief
            /// ServerUDPSocket only listens for connections.
            virtual std::size_t WriteMsg (
                    const void *buffer,
                    std::size_t count,
                    const Address &from,
                    const Address &to) {
                assert (0);
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "%s", "ServerUDPSocket can't WriteMsg.");
                return -1;
            }
            /// \brief
            /// ServerUDPSocket only listens for connections.
            virtual void WriteBufferMsg (
                    util::Buffer buffer,
                    const Address &from,
                    const Address &to) {
                assert (0);
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "%s", "ServerUDPSocket can't WriteBufferMsg.");
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
            THEKOGANS_STREAM_DISALLOW_COPY_AND_ASSIGN (ServerUDPSocket)
        };

    } // namespace stream
} // namespace thekogans

#endif // !defined (__thekogans_stream_ServerUDPSocket_h)
