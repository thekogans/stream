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
#include "thekogans/util/Environment.h"
#include "thekogans/util/XMLUtils.h"
#include "thekogans/util/Path.h"
#include "thekogans/util/Exception.h"
#include "thekogans/stream/AsyncIoEventQueue.h"
#include "thekogans/stream/AsyncIoEventSink.h"
#include "thekogans/stream/ServerTCPSocket.h"

namespace thekogans {
    namespace stream {

        THEKOGANS_STREAM_IMPLEMENT_STREAM (ServerTCPSocket)

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

        TCPSocket::SharedPtr ServerTCPSocket::Accept () {
            if (IsAsync ()) {
            #if defined (TOOLCHAIN_OS_Windows)
                PostAsyncAccept ();
            #else // defined (TOOLCHAIN_OS_Windows)
                AsyncIoEventQueue::Instance ()->AddStreamForEvents (*this, AsyncInfo::EventRead);
            #endif // defined (TOOLCHAIN_OS_Windows)
                return TCPSocket::SharedPtr ();
            }
            else {
                TCPSocket::SharedPtr connection (
                    new TCPSocket ((THEKOGANS_UTIL_HANDLE)TCPSocket::Accept ()));
            #if defined (TOOLCHAIN_OS_Windows)
                connection->UpdateAcceptContext (handle);
            #endif // defined (TOOLCHAIN_OS_Windows)
                return connection;
            }
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
                    TCPSocket::SharedPtr connection =
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
                    TCPSocket::SharedPtr connection =
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
