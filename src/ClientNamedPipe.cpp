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

#include <sstream>
#include "thekogans/util/XMLUtils.h"
#include "thekogans/util/Exception.h"
#include "thekogans/util/WindowsUtils.h"
#include "thekogans/stream/AsyncIoEventQueue.h"
#include "thekogans/stream/ClientNamedPipe.h"

namespace thekogans {
    namespace stream {

        THEKOGANS_STREAM_IMPLEMENT_STREAM (ClientNamedPipe)

        const char * const ClientNamedPipe::Context::VALUE_CLIENT_NAMED_PIPE =
            "ClientNamedPipe";
        const char * const ClientNamedPipe::Context::TAG_PIPE_TYPE = "PipeType";
        const char * const ClientNamedPipe::Context::VALUE_BYTE = "byte";
        const char * const ClientNamedPipe::Context::VALUE_MESSAGE = "message";

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
                    }
                }
            }
            else {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "Unexpected context type: %s (%s)",
                    type.c_str (),
                    VALUE_CLIENT_NAMED_PIPE);
            }
        }

        std::string ClientNamedPipe::Context::ToString (
                std::size_t indentationLevel,
                const char *tagName) const {
            if (tagName != 0) {
                std::ostringstream stream;
                stream <<
                    Stream::Context::ToString (indentationLevel, tagName) <<
                        address.ToString (indentationLevel + 1) <<
                        util::OpenTag (indentationLevel + 1, TAG_PIPE_TYPE) <<
                            (pipeType == NamedPipe::Byte ? VALUE_BYTE : VALUE_MESSAGE) <<
                        util::CloseTag (indentationLevel + 1, TAG_PIPE_TYPE) <<
                    util::CloseTag (indentationLevel, tagName);
                return stream.str ();
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        bool ClientNamedPipe::Wait (DWORD timeout) {
            return WaitNamedPipeW (
                util::UTF8ToUTF16 (address.GetPath ()).c_str (),
                timeout) == TRUE;
        }

        void ClientNamedPipe::Connect () {
            if (handle == THEKOGANS_UTIL_INVALID_HANDLE_VALUE) {
                handle = CreateFileW (
                    util::UTF8ToUTF16 (address.GetPath ()).c_str (),
                    GENERIC_READ | GENERIC_WRITE,
                    0,
                    0,
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
                    0);
                if (IsOpen ()) {
                    if (pipeType == Message) {
                        DWORD dwMode = PIPE_READMODE_MESSAGE;
                        if (!SetNamedPipeHandleState (handle, &dwMode, 0, 0)) {
                            THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                                THEKOGANS_UTIL_OS_ERROR_CODE);
                        }
                    }
                }
                else {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_UTIL_OS_ERROR_CODE);
                }
            }
        }

        void ClientNamedPipe::InitAsyncIo () {
            AsyncInfo::Overlapped::Ptr overlapped (
                new AsyncInfo::Overlapped (*this, AsyncInfo::EventConnect));
            if (!PostQueuedCompletionStatus (
                    asyncInfo->eventQueue.GetHandle (),
                    0,
                    (ULONG_PTR)this,
                    overlapped.Get ())) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE);
            }
            overlapped.Release ();
        }

        void ClientNamedPipe::HandleOverlapped (AsyncInfo::Overlapped &overlapped) throw () {
            if (overlapped.event == AsyncInfo::EventConnect) {
                THEKOGANS_UTIL_TRY {
                    PostAsyncRead ();
                    asyncInfo->eventSink.HandleClientNamedPipeConnected (*this);
                }
                THEKOGANS_UTIL_CATCH (util::Exception) {
                    THEKOGANS_UTIL_EXCEPTION_NOTE_LOCATION (exception);
                    asyncInfo->eventSink.HandleStreamError (*this, exception);
                }
            }
            else {
                NamedPipe::HandleOverlapped (overlapped);
            }
        }

    } // namespace stream
} // namespace thekogans

#endif // defined (TOOLCHAIN_OS_Windows)
