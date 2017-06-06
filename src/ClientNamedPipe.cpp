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

#if defined (TOOLCHAIN_OS_Windows)

#include <cassert>
#include <sstream>
#include "thekogans/util/Exception.h"
#include "thekogans/util/XMLUtils.h"
#include "thekogans/stream/ClientNamedPipe.h"

namespace thekogans {
    namespace stream {

        THEKOGANS_STREAM_IMPLEMENT_STREAM (ClientNamedPipe)

    #if defined (THEKOGANS_STREAM_HAVE_PUGIXML)
        const char * const ClientNamedPipe::Context::VALUE_CLIENT_NAMED_PIPE =
            "ClientNamedPipe";
        const char * const ClientNamedPipe::Context::TAG_PIPE_TYPE = "PipeType";
        const char * const ClientNamedPipe::Context::VALUE_BYTE = "byte";
        const char * const ClientNamedPipe::Context::VALUE_MESSAGE = "message";
        const char * const ClientNamedPipe::Context::TAG_TIMEOUT = "Timeout";

        void ClientNamedPipe::Context::Parse (const pugi::xml_node &node) {
            Stream::Context::Parse (node);
            assert (type == VALUE_CLIENT_NAMED_PIPE);
            if (type == VALUE_CLIENT_NAMED_PIPE) {
                for (pugi::xml_node child = node.first_child ();
                        !child.empty (); child = child.next_sibling ()) {
                    if (child.type () == pugi::node_element) {
                        std::string childName = child.name ();
                        if (childName == Address::TAG_ADDRESS) {
                            address.Parse (child);
                            assert (address.GetFamily () == AF_LOCAL);
                        }
                        else if (childName == TAG_PIPE_TYPE) {
                            pipeType = std::string (child.text ().get ()) == VALUE_BYTE ?
                                NamedPipe::Byte : NamedPipe::Message;
                        }
                        else if (childName == TAG_TIMEOUT) {
                            timeout = util::stringToui32 (child.text ().get ());
                        }
                    }
                }
            }
        }

        std::string ClientNamedPipe::Context::ToString (
                util::ui32 indentationLevel,
                const char *tagName) const {
            assert (tagName != 0);
            std::ostringstream stream;
            stream <<
                Stream::Context::ToString (indentationLevel, tagName) <<
                    address.ToString (indentationLevel + 1) <<
                    util::OpenTag (indentationLevel + 1, TAG_PIPE_TYPE) <<
                        (pipeType == NamedPipe::Byte ? VALUE_BYTE : VALUE_MESSAGE) <<
                    util::CloseTag (indentationLevel + 1, TAG_PIPE_TYPE) <<
                    util::OpenTag (indentationLevel + 1, TAG_TIMEOUT) <<
                        util::ui32Tostring (timeout) <<
                    util::CloseTag (indentationLevel + 1, TAG_TIMEOUT) <<
                util::CloseTag (indentationLevel, tagName);
            return stream.str ();
        }
    #endif // defined (THEKOGANS_STREAM_HAVE_PUGIXML)

        ClientNamedPipe::ClientNamedPipe (
                const Address &address,
                PipeType pipeType,
                DWORD timeout) {
            while (!IsOpen ()) {
                handle = CreateFile (address.GetPath ().c_str (), GENERIC_READ | GENERIC_WRITE,
                    0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, 0);
                if (IsOpen () || THEKOGANS_UTIL_OS_ERROR_CODE != ERROR_PIPE_BUSY ||
                        !WaitNamedPipe (address.GetPath ().c_str (), timeout)) {
                    break;
                }
            }
            if (!IsOpen ()) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE);
            }
            if (pipeType == Message) {
                DWORD dwMode = PIPE_READMODE_MESSAGE;
                if (!SetNamedPipeHandleState (handle, &dwMode, 0, 0)) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_UTIL_OS_ERROR_CODE);
                }
            }
        }

    } // namespace stream
} // namespace thekogans

#endif // defined (TOOLCHAIN_OS_Windows)
