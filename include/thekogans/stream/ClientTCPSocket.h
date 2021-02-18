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

#if !defined (__thekogans_stream_ClientTCPSocket_h)
#define __thekogans_stream_ClientTCPSocket_h

#include <string>
#include "pugixml/pugixml.hpp"
#include "thekogans/util/Types.h"
#include "thekogans/stream/Config.h"
#include "thekogans/stream/TCPSocket.h"

namespace thekogans {
    namespace stream {

        /// \struct ClientTCPSocket ClientTCPSocket.h thekogans/stream/ClientTCPSocket.h
        ///
        /// \brief
        /// ClientTCPSocket exposes an Context you can use to create client
        /// side TCPSocket from rest. Use it to instantiate a TCPSocket from
        /// a configuration file. Other than that, ClientTCPSocket defers to
        /// TCPSocket. (as a mater of fact, ClientTCPSocket::Context::CreateStream
        /// creates \see{TCPSocket} and not a ClientTCPSocket!

        struct _LIB_THEKOGANS_STREAM_DECL ClientTCPSocket : public TCPSocket {
            /// \brief
            /// ClientTCPSocket participates in the \see{Stream} dynamic
            /// discovery and creation.
            THEKOGANS_STREAM_DECLARE_STREAM (ClientTCPSocket)

            /// \struct ClientTCPSocket::Context ClientTCPSocket.h thekogans/stream/ClientTCPSocket.h
            ///
            /// \brief
            /// ClientTCPSocket::Context represents the state
            /// of a ClientTCPSocket at rest. At any time you want
            /// to reconstitute a ClientTCPSocket from rest,
            /// feed a parsed (pugi::xml_node) one of:
            /// <tagName StreamType = "ClientTCPSocket"
            ///          Family = ""
            ///          Type = ""
            ///          Protocol = "">
            ///     <Address Family = "inet | inet6"
            ///              Port = ""
            ///              Addr = "an inet or inet6 formated address, or host name"/>
            ///     or
            ///     <Address Family = "local"
            ///              Path = ""/>
            /// </tagName>
            /// to: Stream::GetContext (const pugi::xml_node &node), and it
            /// will return back to you a properly constructed and initialized
            /// ClientTCPSocket::Context. Call Context::CreateStream () to
            /// recreate a ClientTCPSocket from rest. Where you go with
            /// it from there is entirely up to you, but may I recommend:
            /// \see{AsyncIoEventQueue}.
            struct _LIB_THEKOGANS_STREAM_DECL Context : public Socket::Context {
                /// \brief
                /// Declare \see{RefCounted} pointers.
                THEKOGANS_UTIL_DECLARE_REF_COUNTED_POINTERS (Context)

                /// \brief
                /// "ClientTCPSocket".
                static const char * const VALUE_CLIENT_TCP_SOCKET;

                /// \brief
                /// \see{Address} to connect to.
                Address address;

                /// \brief
                /// ctor. Parse the node representing a ClientTCPSocket::Context.
                /// \param[in] node pugi::xml_node representing
                /// a ClientTCPSocket::Context.
                explicit Context (const pugi::xml_node &node) :
                        Socket::Context (VALUE_CLIENT_TCP_SOCKET, 0, 0, 0),
                        address (Address::Empty) {
                    Parse (node);
                }
                /// \brief
                /// ctor.
                /// \param[in] address_ \see{Address} to connect to.
                explicit Context (const Address &address_) :
                        Socket::Context (
                            VALUE_CLIENT_TCP_SOCKET,
                            address_.GetFamily (),
                            SOCK_STREAM,
                            0),
                    address (address_) {}

                /// \brief
                /// Parse the node representing a ClientTCPSocket::Context.
                /// \param[in] node pugi::xml_node representing
                /// a ClientTCPSocket::Context.
                virtual void Parse (const pugi::xml_node &node);
                /// \brief
                /// Return a string representing the rest
                /// state of the ClientTCPSocket.
                /// \param[in] indentationLevel Pretty print parameter.
                /// indents the tag with 4 * indentationLevel spaces.
                /// \param[in] tagName Tag name (default to "Context").
                /// \return String representing the rest state of the
                /// ClientTCPSocket.
                virtual std::string ToString (
                    std::size_t indentationLevel = 0,
                    const char *tagName = TAG_CONTEXT) const;

                /// \brief
                /// Create a \see{TCPSocket} based on address.GetFamily ().
                /// NOTE: The new \see{TCPSocket} is not connected. This is on
                /// purpose as you might want to call \see{TCPSocket::Connect}
                /// asynchronously.
                /// \return \see{TCPSocket} based on address.GetFamily ().
                virtual Stream::SharedPtr CreateStream () const;
            };

            /// \brief
            /// ctor.
            /// Wrap an OS handle.
            /// \param[in] handle OS stream handle to wrap.
            ClientTCPSocket (THEKOGANS_UTIL_HANDLE handle = THEKOGANS_UTIL_INVALID_HANDLE_VALUE) :
                TCPSocket (handle) {}
            /// \brief
            /// ctor.
            /// \param[in] family Socket family specification.
            /// \param[in] type Socket type specification.
            /// \param[in] protocol Socket protocol specification.
            ClientTCPSocket (
                int family,
                int type,
                int protocol) :
                TCPSocket (family, type, protocol) {}

            /// \brief
            /// Streams are neither copy constructable, nor assignable.
            THEKOGANS_STREAM_DISALLOW_COPY_AND_ASSIGN (ClientTCPSocket)
        };

    } // namespace stream
} // namespace thekogans

#endif // !defined (__thekogans_stream_ClientTCPSocket_h)
