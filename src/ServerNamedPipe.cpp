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
#include "thekogans/util/Exception.h"
#include "thekogans/util/XMLUtils.h"
#include "thekogans/stream/AsyncIoEventSink.h"
#include "thekogans/stream/ServerNamedPipe.h"

namespace thekogans {
    namespace stream {

        THEKOGANS_STREAM_IMPLEMENT_STREAM (ServerNamedPipe)

    #if defined (THEKOGANS_STREAM_HAVE_PUGIXML)
        const char * const ServerNamedPipe::Context::VALUE_SERVER_NAMED_PIPE =
            "ServerNamedPipe";
        const char * const ServerNamedPipe::Context::TAG_PIPE_TYPE = "PipeType";
        const char * const ServerNamedPipe::Context::VALUE_BYTE = "byte";
        const char * const ServerNamedPipe::Context::VALUE_MESSAGE = "message";
        const char * const ServerNamedPipe::Context::TAG_BUFFER_SIZE = "BufferSize";

        void ServerNamedPipe::Context::Parse (const pugi::xml_node &node) {
            Stream::Context::Parse (node);
            assert (type == VALUE_SERVER_NAMED_PIPE);
            if (type == VALUE_SERVER_NAMED_PIPE) {
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
                        else if (childName == TAG_BUFFER_SIZE) {
                            bufferSize = util::stringToui32 (child.text ().get ());
                        }
                    }
                }
            }
        }

        std::string ServerNamedPipe::Context::ToString (
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
                    util::OpenTag (indentationLevel + 1, TAG_BUFFER_SIZE) <<
                        util::ui32Tostring (bufferSize) <<
                    util::CloseTag (indentationLevel + 1, TAG_BUFFER_SIZE) <<
                util::CloseTag (indentationLevel, tagName);
            return stream.str ();
        }
    #endif // defined (THEKOGANS_STREAM_HAVE_PUGIXML)

        ServerNamedPipe::ServerNamedPipe (
                const Address &address_,
                PipeType pipeType_,
                DWORD bufferSize_) :
                address (address_),
                pipeType (pipeType_),
                bufferSize (bufferSize_) {
            SECURITY_DESCRIPTOR sd;
            InitializeSecurityDescriptor (&sd, SECURITY_DESCRIPTOR_REVISION);
            SetSecurityDescriptorDacl (&sd, TRUE, 0, FALSE);
            SECURITY_ATTRIBUTES sa;
            sa.nLength = sizeof (SECURITY_ATTRIBUTES);
            sa.bInheritHandle = FALSE;
            sa.lpSecurityDescriptor = &sd;
            DWORD dwPipeMode = PIPE_WAIT;
            if (pipeType == Byte) {
                dwPipeMode |= PIPE_TYPE_BYTE | PIPE_READMODE_BYTE;
            }
            else {
                dwPipeMode |= PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE;
            }
            handle = CreateNamedPipe (address.GetPath ().c_str (),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                dwPipeMode, PIPE_UNLIMITED_INSTANCES,
                bufferSize, bufferSize, INFINITE, &sa);
            if (!IsOpen ()) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE);
            }
        }

        ServerNamedPipe::~ServerNamedPipe () {
            THEKOGANS_UTIL_TRY {
                Close ();
            }
            THEKOGANS_UTIL_CATCH_AND_LOG_SUBSYSTEM (THEKOGANS_STREAM)
        }

        void ServerNamedPipe::Close () {
            if (IsOpen ()) {
                if (FlushFileBuffers (handle)) {
                    DisconnectNamedPipe (handle);
                    handle = THEKOGANS_UTIL_INVALID_HANDLE_VALUE;
                }
                else {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_UTIL_OS_ERROR_CODE);
                }
            }
        }

        void ServerNamedPipe::Connect () {
            AsyncInfo::Overlapped::UniquePtr overlapped;
            if (IsAsync ()) {
                overlapped.reset (
                    new AsyncInfo::Overlapped (*this, AsyncInfo::EventConnect));
            }
            if (!ConnectNamedPipe (handle, overlapped.get ())) {
                THEKOGANS_UTIL_ERROR_CODE errorCode = THEKOGANS_UTIL_OS_ERROR_CODE;
                if (errorCode != ERROR_IO_PENDING) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (errorCode);
                }
            }
            overlapped.release ();
        }

        ServerNamedPipe::Ptr ServerNamedPipe::Clone () const {
            return ServerNamedPipe::Ptr (
                new ServerNamedPipe (address, pipeType, bufferSize));
        }

        void ServerNamedPipe::InitAsyncIo () {
            Connect ();
        }

        void ServerNamedPipe::HandleOverlapped (AsyncInfo::Overlapped &overlapped) throw () {
            if (overlapped.event == AsyncInfo::EventConnect) {
                THEKOGANS_UTIL_TRY {
                    PostAsyncRead ();
                    asyncInfo->eventSink.HandleServerNamedPipeConnection (*this);
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
