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

        void ClientTCPSocket::Connect (const Address &address) {
        #if defined (TOOLCHAIN_OS_Windows)
            if (IsAsync ()) {
                THEKOGANS_UTIL_TRY {
                    // Asshole M$ strikes again. Wasted a significant
                    // portion of my life chasing a bug that wound up
                    // being that ConnectEx needs the socket to be
                    // explicitly bound.
                    if (!IsBound ()) {
                        Bind (Address::Any (0, address.GetFamily ()));
                    }
                    ConnectOverlapped::SharedPtr overlapped (new ConnectOverlapped (*this, address));
                    if (!WindowsFunctions::Instance ().ConnectEx (
                            (THEKOGANS_STREAM_SOCKET)handle,
                            &overlapped->address.address,
                            overlapped->address.length,
                            0,
                            0,
                            0,
                            overlapped.Get ())) {
                        THEKOGANS_UTIL_ERROR_CODE errorCode = THEKOGANS_STREAM_SOCKET_ERROR_CODE;
                        if (errorCode != WSA_IO_PENDING) {
                            THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (errorCode);
                        }
                    }
                    overlapped.Release ();
                }
                THEKOGANS_UTIL_CATCH (util::Exception) {
                    THEKOGANS_UTIL_EXCEPTION_NOTE_LOCATION (exception);
                    Produce (
                        std::bind (
                            &StreamEvents::OnStreamError,
                            std::placeholders::_1,
                            SharedPtr (this),
                            exception));
                }
            }
            else {
                if (WSAConnect ((THEKOGANS_STREAM_SOCKET)handle, &address.address,
                        address.length, 0, 0, 0, 0) == THEKOGANS_STREAM_SOCKET_ERROR) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                }
            }
        #else // defined (TOOLCHAIN_OS_Windows)
            THEKOGANS_UTIL_TRY {
                if (IsAsync ()) {
                    AsyncIoEventQueue::Instance ().AddStreamForEvents (AsyncInfo::EventConnect);
                }
                if (connect ((THEKOGANS_STREAM_SOCKET)handle, &address.address, address.length) ==
                        THEKOGANS_STREAM_SOCKET_ERROR) {
                    THEKOGANS_UTIL_ERROR_CODE errorCode = THEKOGANS_STREAM_SOCKET_ERROR_CODE;
                    if (errorCode != EINPROGRESS) {
                        THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (errorCode);
                    }
                }
            }
            THEKOGANS_UTIL_CATCH (util::Exception) {
                THEKOGANS_UTIL_EXCEPTION_NOTE_LOCATION (exception);
                if (IsAsync ()) {
                    Produce (
                        std::bind (
                            &StreamEvents::OnStreamError,
                            std::placeholders::_1,
                            SharedPtr (this),
                            exception));
                }
                else {
                    THEKOGANS_UTIL_RETHROW_EXCEPTION (exception);
                }
            }
        #endif // defined (TOOLCHAIN_OS_Windows)
        }

    #if defined (TOOLCHAIN_OS_Windows)
        void ClientTCPSocket::HandleOverlapped (AsyncInfo::Overlapped &overlapped) throw () {
            if (overlapped.event == AsyncInfo::EventConnect) {
                THEKOGANS_UTIL_TRY {
                    UpdateConnectContext ();
                    Produce (
                        std::bind (
                            &ClientTCPSocketEvents::OnTCPSocketConnected,
                            std::placeholders::_1,
                            SharedPtr (this)));
                }
                THEKOGANS_UTIL_CATCH (util::Exception) {
                    THEKOGANS_UTIL_EXCEPTION_NOTE_LOCATION (exception);
                    Produce (
                        std::bind (
                            &StreamEvents::OnStreamError,
                            std::placeholders::_1,
                            SharedPtr (this),
                            exception));
                }
            }
            else {
                TCPSocket::HandleAsyncEvent (event);
            }
        }
    #else // defined (TOOLCHAIN_OS_Windows)
        void ClientTCPSocket::HandleAsyncEvent (util::ui32 event) throw () {
            if (event == AsyncInfo::EventConnect) {
                THEKOGANS_UTIL_TRY {
                    AsyncIoEventQueue::Instance ().DeleteStreamForEvents (AsyncInfo::EventConnect);
                    Produce (
                        std::bind (
                            &StreamEvents::OnTCPSocketConnected,
                            std::placeholders::_1,
                            SharedPtr (this)));
                }
                THEKOGANS_UTIL_CATCH (util::Exception) {
                    THEKOGANS_UTIL_EXCEPTION_NOTE_LOCATION (exception);
                    Produce (
                        std::bind (
                            &StreamEvents::OnStreamError,
                            std::placeholders::_1,
                            SharedPtr (this),
                            exception));
                }
            }
            else {
                TCPSocket::HandleAsyncEvent (event);
            }
        }
    #endif // defined (TOOLCHAIN_OS_Windows)

    } // namespace stream
} // namespace thekogans
