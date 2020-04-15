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
#include "thekogans/util/Path.h"
#include "thekogans/util/Exception.h"
#include "thekogans/stream/AsyncIoEventQueue.h"
#include "thekogans/stream/AsyncIoEventSink.h"
#include "thekogans/stream/ServerTCPSocket.h"

namespace thekogans {
    namespace stream {

        THEKOGANS_STREAM_IMPLEMENT_STREAM (ServerTCPSocket)

        const char * const ServerTCPSocket::Context::VALUE_SERVER_TCP_SOCKET = "ServerTCPSocket";
        const char * const ServerTCPSocket::Context::TAG_REUSE_ADDRESS = "ReuseAddress";
        const char * const ServerTCPSocket::Context::TAG_MAX_PENDING_CONNECTIONS = "MaxPendingConnections";

        void ServerTCPSocket::Context::Parse (const pugi::xml_node &node) {
            Stream::Context::Parse (node);
            for (pugi::xml_node child = node.first_child ();
                    !child.empty (); child = child.next_sibling ()) {
                if (child.type () == pugi::node_element) {
                    std::string childName = child.name ();
                    if (childName == Address::TAG_ADDRESS) {
                        address.Parse (child);
                    }
                    else if (childName == TAG_REUSE_ADDRESS) {
                        reuseAddress = std::string (child.text ().get ()) == util::XML_TRUE;
                    }
                    else if (childName == TAG_MAX_PENDING_CONNECTIONS) {
                        maxPendingConnections = util::stringToui32 (child.text ().get ());
                    }
                }
            }
        }

        std::string ServerTCPSocket::Context::ToString (
                std::size_t indentationLevel,
                const char *tagName) const {
            if (tagName != 0) {
                std::ostringstream stream;
                stream <<
                    Stream::Context::ToString (indentationLevel, tagName) <<
                        address.ToString (indentationLevel + 1) <<
                        util::OpenTag (indentationLevel + 1, TAG_REUSE_ADDRESS) <<
                            util::boolTostring (reuseAddress) <<
                        util::CloseTag (indentationLevel + 1, TAG_REUSE_ADDRESS) <<
                        util::OpenTag (indentationLevel + 1, TAG_MAX_PENDING_CONNECTIONS) <<
                            util::i32Tostring (maxPendingConnections) <<
                        util::CloseTag (indentationLevel + 1, TAG_MAX_PENDING_CONNECTIONS) <<
                    util::CloseTag (indentationLevel, tagName);
                return stream.str ();
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        Stream::Ptr ServerTCPSocket::Context::CreateStream () const {
            return Stream::Ptr (
                new ServerTCPSocket (address, reuseAddress, maxPendingConnections));
        }

        ServerTCPSocket::ServerTCPSocket (
                const Address &address,
                bool reuseAddress,
                util::ui32 maxPendingConnections) :
                TCPSocket (address.GetFamily (), SOCK_STREAM, 0) {
            if (reuseAddress) {
            #if !defined (TOOLCHAIN_OS_Windows)
                if (address.GetFamily () == AF_LOCAL) {
                    util::Path path (address.GetPath ());
                    if (path.Exists ()) {
                        // Can't use Path::Delete here as the file is a device and
                        // Path only supports directories and files.
                        unlink (address.GetPath ().c_str ());
                    }
                }
                else {
            #endif // !define (TOOLCHAIN_OS_Windows)
                    SetReuseAddress (true);
            #if !defined (TOOLCHAIN_OS_Windows)
                }
            #endif // !defined (TOOLCHAIN_OS_Windows)
            }
            Bind (address);
            Listen (maxPendingConnections);
        }

        TCPSocket::Ptr ServerTCPSocket::Accept () {
            if (!IsAsync ()) {
                TCPSocket::Ptr connection (
                    new TCPSocket ((THEKOGANS_UTIL_HANDLE)TCPSocket::Accept ()));
            #if defined (TOOLCHAIN_OS_Windows)
                connection->UpdateAcceptContext (handle);
            #endif // defined (TOOLCHAIN_OS_Windows)
                return connection;
            }
            else {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "%s", "Accept is called on a non-blocking socket.");
            }
        }

        void ServerTCPSocket::InitAsyncIo () {
        #if defined (TOOLCHAIN_OS_Windows)
            PostAsyncAccept ();
        #else // defined (TOOLCHAIN_OS_Windows)
            SetBlocking (false);
            asyncInfo->AddStreamForEvents (AsyncInfo::EventRead);
        #endif // defined (TOOLCHAIN_OS_Windows)
        }

    #if defined (TOOLCHAIN_OS_Windows)
        void ServerTCPSocket::HandleOverlapped (AsyncInfo::Overlapped &overlapped) throw () {
            if (overlapped.event == AsyncInfo::EventConnect) {
                THEKOGANS_UTIL_TRY {
                    PostAsyncAccept ();
                    TCPSocket::AcceptOverlapped &acceptOverlapped =
                        (TCPSocket::AcceptOverlapped &)overlapped;
                    TCPSocket::UpdateAcceptContext (handle,
                        (THEKOGANS_UTIL_HANDLE)acceptOverlapped.connection);
                    TCPSocket::Ptr connection =
                        asyncInfo->eventSink.GetTCPSocket (
                            (THEKOGANS_UTIL_HANDLE)acceptOverlapped.connection);
                    // Overlapped::AcceptInfo::~AcceptInfo will
                    // close an unclaimed socket. Set it to
                    // THEKOGANS_STREAM_INVALID_SOCKET to let
                    // it know that we did in fact claimed it.
                    acceptOverlapped.connection = THEKOGANS_STREAM_INVALID_SOCKET;
                    asyncInfo->eventSink.HandleServerTCPSocketConnection (*this, connection);
                }
                THEKOGANS_UTIL_CATCH (util::Exception) {
                    THEKOGANS_UTIL_EXCEPTION_NOTE_LOCATION (exception);
                    asyncInfo->eventSink.HandleStreamError (*this, exception);
                }
            }
        }
    #else // defined (TOOLCHAIN_OS_Windows)
        void ServerTCPSocket::HandleAsyncEvent (util::ui32 event) throw () {
            if (event == AsyncInfo::EventRead) {
                THEKOGANS_UTIL_TRY {
                    TCPSocket::Ptr connection =
                        asyncInfo->eventSink.GetTCPSocket (TCPSocket::Accept ());
                    // Connections inherit the listening socket's
                    // non-blocking state. Since we handle all
                    // async io through AsyncIoEventQueue, set the
                    // connection to blocking. If the caller
                    // decides to make the connection async, they
                    // will call AsyncIoEventQueue::AddStream
                    // explicitly.
                    connection->SetBlocking (true);
                    asyncInfo->eventSink.HandleServerTCPSocketConnection (
                        *this, connection);
                }
                THEKOGANS_UTIL_CATCH (util::Exception) {
                    THEKOGANS_UTIL_EXCEPTION_NOTE_LOCATION (exception);
                    asyncInfo->eventSink.HandleStreamError (*this, exception);
                }
            }
        }
    #endif // defined (TOOLCHAIN_OS_Windows)

    } // namespace stream
} // namespace thekogans
