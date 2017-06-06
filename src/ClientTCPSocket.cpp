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

#if defined (THEKOGANS_STREAM_HAVE_PUGIXML)

#include <sstream>
#include "thekogans/util/XMLUtils.h"
#include "thekogans/stream/ClientTCPSocket.h"

namespace thekogans {
    namespace stream {

        THEKOGANS_STREAM_IMPLEMENT_STREAM (ClientTCPSocket)

        const char * const ClientTCPSocket::OpenInfo::VALUE_CLIENT_TCP_SOCKET =
            "ClientTCPSocket";

        void ClientTCPSocket::OpenInfo::Parse (const pugi::xml_node &node) {
            Stream::OpenInfo::Parse (node);
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

        std::string ClientTCPSocket::OpenInfo::ToString (
                util::ui32 indentationLevel,
                const char *tagName) const {
            assert (tagName != 0);
            std::ostringstream stream;
            stream <<
                Stream::OpenInfo::ToString (indentationLevel, tagName) <<
                    address.ToString (indentationLevel + 1) <<
                util::CloseTag (indentationLevel, tagName);
            return stream.str ();
        }

        Stream::Ptr ClientTCPSocket::OpenInfo::CreateStream () const {
            return Stream::Ptr (
                new TCPSocket (address.GetFamily (), SOCK_STREAM, IPPROTO_TCP));
        }

    } // namespace stream
} // namespace thekogans

#endif // defined (THEKOGANS_STREAM_HAVE_PUGIXML)

