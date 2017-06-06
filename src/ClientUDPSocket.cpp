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

#include <sstream>
#include "thekogans/util/XMLUtils.h"
#include "thekogans/stream/ClientUDPSocket.h"

namespace thekogans {
    namespace stream {

        THEKOGANS_STREAM_IMPLEMENT_STREAM (ClientUDPSocket)

    #if defined (THEKOGANS_STREAM_HAVE_PUGIXML)
        const char * const ClientUDPSocket::Context::VALUE_CLIENT_UDP_SOCKET =
            "ClientUDPSocket";

        void ClientUDPSocket::Context::Parse (const pugi::xml_node &node) {
            Stream::Context::Parse (node);
            for (pugi::xml_node child = node.first_child ();
                    !child.empty (); child = child.next_sibling ()) {
                if (child.type () == pugi::node_element) {
                    std::string childName = child.name ();
                    if (childName == Address::TAG_ADDRESS) {
                        address.Parse (child);
                    }
                }
            }
        }

        std::string ClientUDPSocket::Context::ToString (
                util::ui32 indentationLevel,
                const char *tagName) const {
            assert (tagName != 0);
            std::ostringstream stream;
            stream <<
                Stream::Context::ToString (indentationLevel, tagName) <<
                    address.ToString (indentationLevel + 1) <<
                util::CloseTag (indentationLevel, tagName);
            return stream.str ();
        }
    #endif // defined (THEKOGANS_STREAM_HAVE_PUGIXML)

        Stream::Ptr ClientUDPSocket::Context::CreateStream () const {
            return Stream::Ptr (new UDPSocket (address));
        }

    } // namespace stream
} // namespace thekogans
