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

#if !defined (__thekogans_stream_ServerTCPSocket_h)
#define __thekogans_stream_ServerTCPSocket_h

#include <memory>
#include <string>
#include "pugixml/pugixml.hpp"
#include "thekogans/util/Types.h"
#include "thekogans/stream/Config.h"
#include "thekogans/stream/TCPSocket.h"

namespace thekogans {
    namespace stream {

        /// \struct ServerTCPSocket ServerTCPSocket.h thekogans/stream/ServerTCPSocket.h
        ///
        /// \brief
        /// ServerTCPSocket is used to listen for connections from \see{ClientTCPSockets}.

        struct _LIB_THEKOGANS_STREAM_DECL ServerTCPSocket : public TCPSocket {
            /// \brief
            /// ServerTCPSocket participates in the Stream dynamic
            /// discovery and creation.
            THEKOGANS_STREAM_DECLARE_STREAM (ServerTCPSocket)

            /// \struct ServerTCPSocket::Context ServerTCPSocket.h thekogans/stream/ServerTCPSocket.h
            ///
            /// \brief
            /// ServerTCPSocket::Context represents the state
            /// of a ServerTCPSocket at rest. At any time you want
            /// to reconstitute a ServerTCPSocket from rest,
            /// feed a parsed (pugi::xml_node) one of:
            /// <tagName StreamType = "ServerTCPSocket"
            ///          Family = ""
            ///          Type = ""
            ///          Protocol = "">
            ///     <Address Family = "inet | inet6"
            ///              Port = ""
            ///              Addr = "an inet or inet6 formated address, or host name"/>
            ///     or
            ///     <Address Family = "local"
            ///              Path = ""/>
            ///     <ReuseAddress>if true call SetReuseAddress</ReuseAddress>
            ///     <MaxPendingConnections>max pending connection requests</MaxPendingConnections>
            /// </tagName>
            /// to: Stream::GetContext (const pugi::xml_node &node), and it
            /// will return back to you a properly constructed and initialized
            /// ServerTCPSocket::Context. Call Context::CreateStream () to
            /// recreate a ServerTCPSocket from rest. Where you go with
            /// it from there is entirely up to you, but may I recommend:
            /// \see{AsyncIoEventQueue}.
            struct _LIB_THEKOGANS_STREAM_DECL Context : public Socket::Context {
                /// \brief
                /// Declare \see{RefCounted} pointers.
                THEKOGANS_UTIL_DECLARE_REF_COUNTED_POINTERS (Context)

                /// \brief
                /// "ServerTCPSocket"
                static const char * const VALUE_SERVER_TCP_SOCKET;
                /// \brief
                /// "ReuseAddress"
                static const char * const TAG_REUSE_ADDRESS;
                /// \brief
                /// "MaxPendingConnections"
                static const char * const TAG_MAX_PENDING_CONNECTIONS;

                /// \brief
                /// Listening address.
                Address address;
                /// \brief
                /// If true, call \see{Socket::SetReuseAddress} before calling \see{Socket::Bind}.
                bool reuseAddress;
                /// \brief
                /// Max pending connection requests.
                util::i32 maxPendingConnections;

                /// \brief
                /// ctor. Parse the node representing a
                /// ServerTCPSocket::Context.
                /// \param[in] node pugi::xml_node representing
                /// a ServerTCPSocket::Context.
                explicit Context (const pugi::xml_node &node) :
                        Socket::Context (VALUE_SERVER_TCP_SOCKET, 0, 0, 0),
                        address (Address::Empty),
                        reuseAddress (false),
                        maxPendingConnections (TCPSocket::DEFAULT_MAX_PENDING_CONNECTIONS) {
                    Parse (node);
                }
                /// \brief
                /// ctor.
                /// \param[in] family Socket family specification.
                /// \param[in] type Socket type specification.
                /// \param[in] protocol Socket protocol specification.
                /// \param[in] address Listening address.
                /// \param[in] reuseAddress If true, call \see{Socket::SetReuseAddress}
                /// before calling \see{Socket::Bind}.
                /// \param[in] maxPendingConnections Max pending connection requests.
                Context (
                    int family,
                    int type,
                    int protocol,
                    const Address &address_,
                    bool reuseAddress_,
                    util::i32 maxPendingConnections_) :
                    Socket::Context (VALUE_SERVER_TCP_SOCKET, family, type, protocol),
                    address (address_),
                    reuseAddress (reuseAddress_),
                    maxPendingConnections (maxPendingConnections_) {}

                /// \brief
                /// Parse the node representing a
                /// ServerTCPSocket::Context.
                /// \param[in] node pugi::xml_node representing
                /// a ServerTCPSocket::Context.
                virtual void Parse (const pugi::xml_node &node);
                /// \brief
                /// Return a string representing the rest
                /// state of the ServerTCPSocket.
                /// \param[in] indentationLevel Pretty print parameter.
                /// indents the tag with 4 * indentationLevel spaces.
                /// \param[in] tagName Tag name (default to "Context").
                /// \return String representing the rest state of the
                /// ServerTCPSocket.
                virtual std::string ToString (
                    std::size_t indentationLevel = 0,
                    const char *tagName = TAG_CONTEXT) const;

                /// \brief
                /// Create a ServerTCPSocket based on the address and maxPendingConnections.
                /// \return ServerTCPSocket based on the address and maxPendingConnections.
                virtual Stream::SharedPtr CreateStream () const;
            };

            /// \brief
            /// ctor.
            /// Wrap an OS handle.
            /// \param[in] handle OS stream handle to wrap.
            ServerTCPSocket (THEKOGANS_UTIL_HANDLE handle = THEKOGANS_UTIL_INVALID_HANDLE_VALUE) :
                TCPSocket (handle) {}
            /// \brief
            /// ctor.
            /// \param[in] family Socket family specification.
            /// \param[in] type Socket type specification.
            /// \param[in] protocol Socket protocol specification.
            ServerTCPSocket (
                int family,
                int type,
                int protocol) :
                TCPSocket (family, type, protocol) {}
            /// \brief
            /// ctor.
            /// \param[in] address Address to listen on.
            /// \param[in] reuseAddress Call \see{Socket::SetReuseAddress} with this parameter.
            /// \param[in] maxPendingConnections Max pending connection requests.
            ServerTCPSocket (
                const Address &address,
                bool reuseAddress = false,
                util::ui32 maxPendingConnections = TCPSocket::DEFAULT_MAX_PENDING_CONNECTIONS);

            // Stream
            /// \brief
            /// Stop listenning for connection requests.
            virtual void Disconnect () {
                Stream::Disconnect ();
            }

            /// \brief
            /// Wait for connections.
            /// NOTE: This api can only be used by blocking (not async) sockets.
            /// Async sockets go in to listening mode as soon as you add them to
            /// an AsyncIoEventQueue, and return new connections through
            /// AsyncIoEventSink::HandleServerTCPSocketConnection.
            /// \return The new connection.
            TCPSocket::SharedPtr Accept ();

        protected:
            // Stream
            /// \brief
            /// ServerTCPSocket only listens for connections.
            virtual std::size_t Read (
                    void * /*buffer*/,
                    std::size_t /*count*/) {
                assert (0);
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "%s", "ServerTCPSocket can't Read.");
                return -1;
            }
            /// \brief
            /// ServerTCPSocket only listens for connections.
            virtual std::size_t Write (
                    const void * /*buffer*/,
                    std::size_t /*count*/) {
                assert (0);
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "%s", "ServerTCPSocket can't Write.");
                return -1;
            }
            /// \brief
            /// ServerTCPSocket only listens for connections.
            virtual void WriteBuffer (
                    util::Buffer /*buffer*/) {
                assert (0);
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "%s", "ServerTCPSocket can't WriteBuffer.");
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
            THEKOGANS_STREAM_DISALLOW_COPY_AND_ASSIGN (ServerTCPSocket)
        };

    } // namespace stream
} // namespace thekogans

#endif // !defined (__thekogans_stream_ServerTCPSocket_h)
