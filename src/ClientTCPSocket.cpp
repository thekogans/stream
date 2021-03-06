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
#include "thekogans/stream/ClientTCPSocket.h"

namespace thekogans {
    namespace stream {

        THEKOGANS_STREAM_IMPLEMENT_STREAM (ClientTCPSocket)

        const char * const ClientTCPSocket::Context::VALUE_CLIENT_TCP_SOCKET =
            "ClientTCPSocket";

        void ClientTCPSocket::Context::Parse (const pugi::xml_node &node) {
            Socket::Context::Parse (node);
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

        std::string ClientTCPSocket::Context::ToString (
                std::size_t indentationLevel,
                const char *tagName) const {
            if (tagName != 0) {
                std::ostringstream stream;
                stream <<
                    Socket::Context::ToString (indentationLevel, tagName) <<
                        address.ToString (indentationLevel + 1) <<
                    util::CloseTag (indentationLevel, tagName);
                return stream.str ();
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        Stream::SharedPtr ClientTCPSocket::Context::CreateStream () const {
            return Stream::SharedPtr (new TCPSocket (family, type, protocol));
        }

    } // namespace stream
} // namespace thekogans
