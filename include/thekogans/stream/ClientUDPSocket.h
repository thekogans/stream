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

#if !defined (__thekogans_stream_ClientUDPSocket_h)
#define __thekogans_stream_ClientUDPSocket_h

#include <string>
#include "pugixml/pugixml.hpp"
#include "thekogans/util/Types.h"
#include "thekogans/stream/Config.h"
#include "thekogans/stream/UDPSocket.h"

namespace thekogans {
    namespace stream {

        /// \struct ClientUDPSocket ClientUDPSocket.h thekogans/stream/ClientUDPSocket.h
        ///
        /// \brief
        /// ClientUDPSocket exposes an Context you can use to create client
        /// side UDPSocket from rest. Use it to instantiate a UDPSocket from
        /// a configuration file. Other than that, ClientUDPSocket defers to
        /// UDPSocket.

        struct _LIB_THEKOGANS_STREAM_DECL ClientUDPSocket : public UDPSocket {
            /// \brief
            /// ClientUDPSocket participates in the \see{Stream} dynamic
            /// discovery and creation.
            THEKOGANS_STREAM_DECLARE_STREAM (ClientUDPSocket)

            /// \struct ClientUDPSocket::Context ClientUDPSocket.h thekogans/stream/ClientUDPSocket.h
            ///
            /// \brief
            /// ClientUDPSocket::Context represents the state
            /// of a ClientUDPSocket at rest. At any time you want
            /// to reconstitute a ClientUDPSocket from rest,
            /// feed a parsed (pugi::xml_node) one of:
            /// <tagName StreamType = "ClientUDPSocket"
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
            /// ClientUDPSocket::Context. Call Context::CreateStream () to
            /// recreate a ClientUDPSocket from rest. Where you go with
            /// it from there is entirely up to you, but may I recommend:
            /// \see{AsyncIoEventQueue}.
            struct _LIB_THEKOGANS_STREAM_DECL Context : public Socket::Context {
                /// \brief
                /// Declare \see{RefCounted} pointers.
                THEKOGANS_UTIL_DECLARE_REF_COUNTED_POINTERS (Context)

                /// \brief
                /// "ClientUDPSocket".
                static const char * const VALUE_CLIENT_UDP_SOCKET;

                /// \brief
                /// \see{Address} to connect to.
                Address address;

                /// \brief
                /// ctor. Parse the node representing a ClientUDPSocket::Context.
                /// \param[in] node pugi::xml_node representing
                /// a ClientUDPSocket::Context.
                explicit Context (const pugi::xml_node &node) :
                        Socket::Context (VALUE_CLIENT_UDP_SOCKET, 0, 0, 0),
                        address (Address::Empty) {
                    Parse (node);
                }
                /// \brief
                /// ctor.
                /// \param[in] family Socket family specification.
                /// \param[in] type Socket type specification.
                /// \param[in] protocol Socket protocol specification.
                /// \param[in] address_ \see{Address} to connect to.
                Context (
                    int family,
                    int type,
                    int protocol,
                    const Address &address_) :
                    Socket::Context (VALUE_CLIENT_UDP_SOCKET, family, type, protocol),
                    address (address_) {}

                /// \brief
                /// Parse the node representing a ClientUDPSocket::Context.
                /// \param[in] node pugi::xml_node representing
                /// a ClientUDPSocket::Context.
                virtual void Parse (const pugi::xml_node &node);
                /// \brief
                /// Return a string representing the rest
                /// state of the ClientUDPSocket.
                /// \param[in] indentationLevel Pretty print parameter.
                /// indents the tag with 4 * indentationLevel spaces.
                /// \param[in] tagName Tag name (default to "Context").
                /// \return String representing the rest state of the
                /// ClientUDPSocket.
                virtual std::string ToString (
                    std::size_t indentationLevel = 0,
                    const char *tagName = TAG_CONTEXT) const;

                /// \brief
                /// Create a \see{UDPSocket} based on address.GetFamily ().
                /// NOTE: The new \see{UDPSocket} is not connected. This is on
                /// purpose as you might want to call \see{UDPSocket::Connect}
                /// asynchronously.
                /// \return \see{UDPSocket} based on address.GetFamily ().
                virtual Stream::SharedPtr CreateStream () const;
            };

            /// \brief
            /// ctor.
            /// Wrap an OS handle.
            /// \param[in] handle OS stream handle to wrap.
            ClientUDPSocket (THEKOGANS_UTIL_HANDLE handle = THEKOGANS_UTIL_INVALID_HANDLE_VALUE) :
                UDPSocket (handle) {}
            /// \brief
            /// ctor.
            /// \param[in] family Socket family specification.
            /// \param[in] type Socket type specification.
            /// \param[in] protocol Socket protocol specification.
            ClientUDPSocket (
                int family,
                int type,
                int protocol) :
                UDPSocket (family, type, protocol) {}
            /// \brief
            /// ctor.
            /// \param[in] address Socket address.
            explicit ClientUDPSocket (const Address &address) :
                    UDPSocket (Address::Any (0, address.GetFamily ())) {
                Connect (address);
            }

            /// \brief
            /// Streams are neither copy constructable, nor assignable.
            THEKOGANS_STREAM_DISALLOW_COPY_AND_ASSIGN (ClientUDPSocket)
        };

    } // namespace stream
} // namespace thekogans

#endif // !defined (__thekogans_stream_ClientUDPSocket_h)
