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

#if !defined (TOOLCHAIN_OS_Windows)
    #include <sys/ioctl.h>
    #include <netinet/tcp.h>
#endif // !defined (TOOLCHAIN_OS_Windows)
#include <cassert>
#include <cstdio>
#include "thekogans/util/Exception.h"
#include "thekogans/util/LoggerMgr.h"
#include "thekogans/stream/AsyncIoEventQueue.h"
#include "thekogans/stream/AsyncIoEventSink.h"
#include "thekogans/stream/TCPSocket.h"

namespace thekogans {
    namespace stream {

        THEKOGANS_UTIL_IMPLEMENT_HEAP_WITH_LOCK (TCPSocket, util::SpinLock)

    #if defined (TOOLCHAIN_OS_Windows)
        namespace {
            struct WindowsFunctions : public util::Singleton<WindowsFunctions, util::SpinLock> {
                LPFN_CONNECTEX ConnectEx;
                LPFN_DISCONNECTEX DisconnectEx;
                LPFN_ACCEPTEX AcceptEx;

                WindowsFunctions () :
                        ConnectEx (0),
                        DisconnectEx (0),
                        AcceptEx (0) {
                    struct Socket {
                        THEKOGANS_STREAM_SOCKET handle;
                        Socket () :
                                handle (WSASocketW (AF_INET, SOCK_STREAM, IPPROTO_TCP,
                                    0, 0, WSA_FLAG_OVERLAPPED)) {
                            if (handle == THEKOGANS_STREAM_INVALID_SOCKET) {
                                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                            }
                        }
                        ~Socket () {
                            closesocket (handle);
                        }
                    } socket;
                    {
                        GUID GuidConnectEx = WSAID_CONNECTEX;
                        DWORD bytesReturned = 0;
                        if (WSAIoctl (socket.handle,
                                SIO_GET_EXTENSION_FUNCTION_POINTER,
                                &GuidConnectEx, sizeof (GuidConnectEx),
                                &ConnectEx, sizeof (ConnectEx),
                                &bytesReturned, 0, 0) == THEKOGANS_STREAM_SOCKET_ERROR) {
                            THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                                THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                        }
                    }
                    {
                        GUID GuidDisconnectEx = WSAID_DISCONNECTEX;
                        DWORD bytesReturned = 0;
                        if (WSAIoctl (socket.handle,
                                SIO_GET_EXTENSION_FUNCTION_POINTER,
                                &GuidDisconnectEx, sizeof (GuidDisconnectEx),
                                &DisconnectEx, sizeof (DisconnectEx),
                                &bytesReturned, 0, 0) == THEKOGANS_STREAM_SOCKET_ERROR) {
                            THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                                THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                        }
                    }
                    {
                        GUID GuidAcceptEx = WSAID_ACCEPTEX;
                        DWORD bytesReturned = 0;
                        if (WSAIoctl (socket.handle,
                                SIO_GET_EXTENSION_FUNCTION_POINTER,
                                &GuidAcceptEx, sizeof (GuidAcceptEx),
                                &AcceptEx, sizeof (AcceptEx),
                                &bytesReturned, 0, 0) == THEKOGANS_STREAM_SOCKET_ERROR) {
                            THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                                THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                        }
                    }
                }
            };
        }
    #endif // defined (TOOLCHAIN_OS_Windows)

        std::size_t TCPSocket::Read (
                void *buffer,
                std::size_t count) {
            if (buffer != 0 && count > 0) {
            #if defined (TOOLCHAIN_OS_Windows)
                WSABUF wsaBuf = {(ULONG)count, (char *)buffer};
                DWORD numberOfBytesRecvd = 0;
                DWORD flags = 0;
                if (WSARecv ((THEKOGANS_STREAM_SOCKET)handle, &wsaBuf, 1,
                        &numberOfBytesRecvd, &flags, 0, 0) == THEKOGANS_STREAM_SOCKET_ERROR) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                }
                return numberOfBytesRecvd;
            #else // defined (TOOLCHAIN_OS_Windows)
                ssize_t countRead = recv (handle, (char *)buffer, count, 0);
                if (countRead == THEKOGANS_STREAM_SOCKET_ERROR) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                }
                return (std::size_t)countRead;
            #endif // defined (TOOLCHAIN_OS_Windows)
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        std::size_t TCPSocket::Write (
                const void *buffer,
                std::size_t count) {
            if (buffer != 0 && count > 0) {
            #if defined (TOOLCHAIN_OS_Windows)
                DWORD numberOfBytesSent = 0;
                if (IsAsync ()) {
                    PostAsyncWrite (buffer, count);
                }
                else {
                    WSABUF wsaBuf = {(ULONG)count, (char *)buffer};
                    DWORD flags = 0;
                    if (WSASend ((THEKOGANS_STREAM_SOCKET)handle, &wsaBuf, 1,
                            &numberOfBytesSent, flags, 0, 0) == THEKOGANS_STREAM_SOCKET_ERROR) {
                        THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                            THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                    }
                }
                return numberOfBytesSent;
            #else // defined (TOOLCHAIN_OS_Windows)
                ssize_t countWritten = 0;
                if (IsAsync ()) {
                    asyncInfo->EnqBufferBack (
                        AsyncInfo::BufferInfo::UniquePtr (
                            new AsyncInfo::WriteBufferInfo (*this, buffer, count)));
                }
                else {
                    countWritten = send (handle, (const char *)buffer, count, 0);
                    if (countWritten == THEKOGANS_STREAM_SOCKET_ERROR) {
                        THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                            THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                    }
                }
                return (std::size_t)countWritten;
            #endif // defined (TOOLCHAIN_OS_Windows)
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        void TCPSocket::WriteBuffer (util::Buffer buffer) {
            if (!buffer.IsEmpty ()) {
                if (IsAsync ()) {
                #if defined (TOOLCHAIN_OS_Windows)
                    AsyncInfo::ReadWriteOverlapped::UniquePtr overlapped (
                        new AsyncInfo::ReadWriteOverlapped (*this, std::move (buffer)));
                    if (WSASend ((THEKOGANS_STREAM_SOCKET)handle,
                            &overlapped->wsaBuf, 1, 0, 0,
                            overlapped.get (), 0) == THEKOGANS_STREAM_SOCKET_ERROR) {
                        THEKOGANS_UTIL_ERROR_CODE errorCode = THEKOGANS_STREAM_SOCKET_ERROR_CODE;
                        if (errorCode != WSA_IO_PENDING) {
                            THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (errorCode);
                        }
                    }
                    overlapped.release ();
                #else // defined (TOOLCHAIN_OS_Windows)
                    asyncInfo->EnqBufferBack (
                        AsyncInfo::BufferInfo::UniquePtr (
                            new AsyncInfo::WriteBufferInfo (*this, std::move (buffer))));
                #endif // defined (TOOLCHAIN_OS_Windows)
                }
                else {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "%s", "WriteBuffer is called on a blocking socket.");
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        bool TCPSocket::IsConnected () const {
        #if defined (TOOLCHAIN_OS_Windows)
            int arg = 0;
            socklen_t length = sizeof (arg);
            if (getsockopt ((THEKOGANS_STREAM_SOCKET)handle, SOL_SOCKET,
                    SO_CONNECT_TIME, (char *)&arg, &length) == THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
            return arg != 0xffffffff;
        #else // defined (TOOLCHAIN_OS_Windows)
            Address address;
            return getpeername ((THEKOGANS_STREAM_SOCKET)handle,
                &address.address, &address.length) != THEKOGANS_STREAM_SOCKET_ERROR;
        #endif // defined (TOOLCHAIN_OS_Windows)
        }

        void TCPSocket::Connect (const Address &address) {
            if (address != Address::Empty) {
            #if defined (TOOLCHAIN_OS_Windows)
                if (IsAsync ()) {
                    // Asshole M$ strikes again. Wasted a significant
                    // portion of my life chasing a bug that wound up
                    // being that ConnectEx needs the socket to be
                    // explicitly bound.
                    if (!IsBound ()) {
                        Bind (Address::Any (0, address.GetFamily ()));
                    }
                    ConnectOverlapped::UniquePtr overlapped (
                        new ConnectOverlapped (*this, address));
                    if (!WindowsFunctions::Instance ().ConnectEx (
                            (THEKOGANS_STREAM_SOCKET)handle,
                            &overlapped->address.address,
                            overlapped->address.length, 0, 0, 0,
                            overlapped.get ())) {
                        THEKOGANS_UTIL_ERROR_CODE errorCode = THEKOGANS_STREAM_SOCKET_ERROR_CODE;
                        if (errorCode != WSA_IO_PENDING) {
                            THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (errorCode);
                        }
                    }
                    overlapped.release ();
                }
                else {
                    if (WSAConnect ((THEKOGANS_STREAM_SOCKET)handle, &address.address,
                            address.length, 0, 0, 0, 0) == THEKOGANS_STREAM_SOCKET_ERROR) {
                        THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                            THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                    }
                }
            #else // defined (TOOLCHAIN_OS_Windows)
                if (IsAsync ()) {
                    asyncInfo->AddStreamForEvents (AsyncInfo::EventConnect);
                }
                if (connect ((THEKOGANS_STREAM_SOCKET)handle, &address.address, address.length) ==
                        THEKOGANS_STREAM_SOCKET_ERROR) {
                    THEKOGANS_UTIL_ERROR_CODE errorCode = THEKOGANS_STREAM_SOCKET_ERROR_CODE;
                    if (errorCode != EINPROGRESS) {
                        THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (errorCode);
                    }
                }
            #endif // defined (TOOLCHAIN_OS_Windows)
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

    #if defined (TOOLCHAIN_OS_Windows)
        void TCPSocket::Disconnect (bool reuseSocket) {
            AsyncInfo::Overlapped::UniquePtr overlapped;
            if (IsAsync ()) {
                overlapped.reset (new AsyncInfo::Overlapped (*this, AsyncInfo::EventDisconnect));
            }
            if (!WindowsFunctions::Instance ().DisconnectEx (
                    (THEKOGANS_STREAM_SOCKET)handle, overlapped.get (),
                    reuseSocket ? TF_REUSE_SOCKET : 0, 0)) {
                THEKOGANS_UTIL_ERROR_CODE errorCode = THEKOGANS_STREAM_SOCKET_ERROR_CODE;
                if (errorCode != WSA_IO_PENDING) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (errorCode);
                }
            }
            overlapped.release ();
        }
    #endif // defined (TOOLCHAIN_OS_Windows)

        bool TCPSocket::IsListening () const {
            int arg = 0;
            socklen_t length = sizeof (arg);
            if (getsockopt ((THEKOGANS_STREAM_SOCKET)handle, SOL_SOCKET, SO_ACCEPTCONN,
                    (char *)&arg, &length) == THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
            return arg == 1;
        }

        void TCPSocket::Listen (util::i32 maxPendingConnections) {
            if (listen ((THEKOGANS_STREAM_SOCKET)handle, maxPendingConnections) ==
                    THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
        }

        bool TCPSocket::IsKeepAlive () const {
            int arg;
            socklen_t length = sizeof (arg);
            if (getsockopt ((THEKOGANS_STREAM_SOCKET)handle, SOL_SOCKET, SO_KEEPALIVE,
                    (char *)&arg, &length) == THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
            return arg == 1;
        }

    #if defined (TOOLCHAIN_OS_Windows)
        namespace {
            const DWORD DEFAULT_KEEPALIVE_TIME = 0x6DDD00;
            const DWORD DEFAULT_KEEPALIVE_INTERVAL = 0x3E8;

            struct Registry {
                HKEY key;

                Registry (
                        HKEY root,
                        const char *subKey) :
                        key (0) {
                    if (RegOpenKeyEx (root, subKey, 0, KEY_READ, &key) != ERROR_SUCCESS) {
                        THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                            THEKOGANS_UTIL_OS_ERROR_CODE);
                    }
                }
                ~Registry () {
                    RegCloseKey (key);
                }

                DWORD GetDWORD (
                        const char *valueName,
                        DWORD valueDefault) const {
                    DWORD value = 0;
                    DWORD valueSize = sizeof (DWORD);
                    if (RegQueryValueEx (key, valueName, 0, 0,
                            (LPBYTE)&value, &valueSize) != ERROR_SUCCESS) {
                        value = valueDefault;
                    }
                    return value;
                }
            };

            u_long GetKeepAliveTime (util::ui32 idleTime) {
                return idleTime != util::UI32_MAX ?
                    idleTime *= 1000 :
                    Registry (
                        HKEY_LOCAL_MACHINE,
                        "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters").GetDWORD (
                            "KeepAliveTime",
                            DEFAULT_KEEPALIVE_TIME);
            }

            u_long GetKeepAliveTimeInterval (util::ui32 interval) {
                return interval != util::UI32_MAX ?
                    interval *= 1000 :
                    Registry (
                        HKEY_LOCAL_MACHINE,
                        "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters").GetDWORD (
                            "KeepAliveInterval",
                            DEFAULT_KEEPALIVE_INTERVAL);
            }
        }
    #endif // defined (TOOLCHAIN_OS_Windows)

        void TCPSocket::SetKeepAlive (
                bool keepAlive,
                util::ui32 idleTime,
                util::ui32 interval,
                util::ui32 count) {
        #if defined (TOOLCHAIN_OS_Windows)
            // M$ does not allow you to set probe count (it's hard coded to 10).
            tcp_keepalive keepalive = {
                (u_long)(keepAlive ? 1 : 0),
                GetKeepAliveTime (idleTime),
                GetKeepAliveTimeInterval (interval)
            };
            DWORD bytesReturned = 0;
            if (WSAIoctl ((THEKOGANS_STREAM_SOCKET)handle,
                    SIO_KEEPALIVE_VALS, &keepalive, sizeof (keepalive),
                    0, 0, &bytesReturned, 0, 0) == THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
        #else // defined (TOOLCHAIN_OS_Windows)
            u_long arg = keepAlive ? 1 : 0;
            if (setsockopt ((THEKOGANS_STREAM_SOCKET)handle, SOL_SOCKET, SO_KEEPALIVE,
                    (char *)&arg, sizeof (arg)) == THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
            if (keepAlive) {
            #if defined (TOOLCHAIN_OS_Linux)
                static const int option_name = TCP_KEEPIDLE;
            #else // defined (TOOLCHAIN_OS_Linux)
                static const int option_name = TCP_KEEPALIVE;
            #endif // defined (TOOLCHAIN_OS_Linux)
                if (idleTime != util::UI32_MAX &&
                        setsockopt ((THEKOGANS_STREAM_SOCKET)handle, IPPROTO_TCP, option_name,
                            (char *)&idleTime, sizeof (idleTime)) == THEKOGANS_STREAM_SOCKET_ERROR) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                }
                if (interval != util::UI32_MAX &&
                        setsockopt ((THEKOGANS_STREAM_SOCKET)handle, IPPROTO_TCP, TCP_KEEPINTVL,
                            (char *)&interval, sizeof (interval)) == THEKOGANS_STREAM_SOCKET_ERROR) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                }
                if (count != util::UI32_MAX &&
                        setsockopt ((THEKOGANS_STREAM_SOCKET)handle, IPPROTO_TCP, TCP_KEEPCNT,
                            (char *)&count, sizeof (count)) == THEKOGANS_STREAM_SOCKET_ERROR) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                }
            }
        #endif // defined (TOOLCHAIN_OS_Windows)
        }

        bool TCPSocket::IsNagle () const {
            int arg = 0;
            socklen_t length = sizeof (arg);
            if (getsockopt ((THEKOGANS_STREAM_SOCKET)handle, IPPROTO_TCP, TCP_NODELAY,
                    (char *)&arg, &length) == THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
            return arg == 0;
        }

        void TCPSocket::SetNagle (bool nagle) {
            u_long arg = nagle ? 0 : 1;
            if (setsockopt ((THEKOGANS_STREAM_SOCKET)handle, IPPROTO_TCP, TCP_NODELAY,
                    (char *)&arg, sizeof (arg)) == THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
        }

        TCPSocket::Linger TCPSocket::GetLinger () const {
            struct linger l;
            socklen_t length = sizeof (l);
            if (getsockopt ((THEKOGANS_STREAM_SOCKET)handle, SOL_SOCKET, SO_LINGER,
                    (char *)&l, &length) == THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
            return Linger (l.l_onoff != 0, l.l_linger);
        }

        void TCPSocket::SetLinger (const Linger &linger) {
            struct linger l;
            l.l_onoff = linger.on ? 1 : 0;
            l.l_linger = linger.seconds;
            if (setsockopt ((THEKOGANS_STREAM_SOCKET)handle, SOL_SOCKET, SO_LINGER,
                    (char *)&l, sizeof (l)) == THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
        }

        void TCPSocket::Shutdown (ShutdownType shutdownType) {
            int how;
            switch (shutdownType) {
            #if defined (TOOLCHAIN_OS_Windows)
                case ShutdownRead:
                    how = SD_RECEIVE;
                    break;
                case ShutdownWrite:
                    how = SD_SEND;
                    break;
                case ShutdownBoth:
                    how = SD_BOTH;
                    break;
            #else // defined (TOOLCHAIN_OS_Windows)
                case ShutdownRead:
                    how = SHUT_RD;
                    break;
                case ShutdownWrite:
                    how = SHUT_WR;
                    break;
                case ShutdownBoth:
                    how = SHUT_RDWR;
                    break;
            #endif // defined (TOOLCHAIN_OS_Windows)
                default:
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
                    break;
            }
            if (shutdown ((THEKOGANS_STREAM_SOCKET)handle, how) ==
                    THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
        }

        THEKOGANS_STREAM_SOCKET TCPSocket::Accept () {
            THEKOGANS_STREAM_SOCKET connection = THEKOGANS_STREAM_INVALID_SOCKET;
        #if defined (TOOLCHAIN_OS_Windows)
            connection = WSASocketW (GetFamily (), GetType (),
                GetProtocol (), 0, 0, WSA_FLAG_OVERLAPPED);
            char acceptBuffer[256];
            DWORD bytesReceived = 0;
            if (connection != THEKOGANS_STREAM_INVALID_SOCKET) {
                if (!WindowsFunctions::Instance ().AcceptEx (
                        (THEKOGANS_STREAM_SOCKET)handle, connection,
                        acceptBuffer, 0, 128, 128, &bytesReceived, 0)) {
                    THEKOGANS_UTIL_ERROR_CODE errorCode = THEKOGANS_STREAM_SOCKET_ERROR_CODE;
                    closesocket (connection);
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (errorCode);
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
        #else // defined (TOOLCHAIN_OS_Windows)
            connection = accept ((THEKOGANS_STREAM_SOCKET)handle, 0, 0);
            if (connection == THEKOGANS_STREAM_INVALID_SOCKET) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
        #endif // defined (TOOLCHAIN_OS_Windows)
            return connection;
        }

        void TCPSocket::InitAsyncIo () {
        #if defined (TOOLCHAIN_OS_Windows)
            if (IsConnected ()) {
                PostAsyncRead ();
            }
        #else // defined (TOOLCHAIN_OS_Windows)
            SetBlocking (false);
            asyncInfo->AddStreamForEvents (
                AsyncInfo::EventDisconnect | AsyncInfo::EventRead);
        #endif // defined (TOOLCHAIN_OS_Windows)
        }

    #if defined (TOOLCHAIN_OS_Windows)
        THEKOGANS_UTIL_IMPLEMENT_HEAP_WITH_LOCK (TCPSocket::ConnectOverlapped, util::SpinLock)
        THEKOGANS_UTIL_IMPLEMENT_HEAP_WITH_LOCK (TCPSocket::AcceptOverlapped, util::SpinLock)

        void TCPSocket::UpdateConnectContext () {
            if (setsockopt ((THEKOGANS_STREAM_SOCKET)handle, SOL_SOCKET,
                    SO_UPDATE_CONNECT_CONTEXT, 0, 0) == THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
        }

        void TCPSocket::UpdateAcceptContext (THEKOGANS_UTIL_HANDLE listenningSocket) {
            UpdateAcceptContext (listenningSocket, handle);
        }

        void TCPSocket::UpdateAcceptContext (
                THEKOGANS_UTIL_HANDLE listenningSocket,
                THEKOGANS_UTIL_HANDLE acceptedSocket) {
            if (setsockopt ((THEKOGANS_STREAM_SOCKET)acceptedSocket, SOL_SOCKET,
                    SO_UPDATE_ACCEPT_CONTEXT, (char *)&listenningSocket,
                    sizeof (listenningSocket)) == THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
        }

        bool TCPSocket::IsBound () const {
            Address address;
            return getsockname ((THEKOGANS_STREAM_SOCKET)handle,
                (sockaddr *)&address.storage, &address.length) == 0;
        }

        void TCPSocket::PostAsyncRead (bool useGetBuffer) {
            AsyncInfo::ReadWriteOverlapped::UniquePtr overlapped (
                new AsyncInfo::ReadWriteOverlapped (*this, asyncInfo->bufferLength, useGetBuffer));
            if (WSARecv ((THEKOGANS_STREAM_SOCKET)handle, &overlapped->wsaBuf, 1, 0,
                    &overlapped->flags, overlapped.get (), 0) == THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_ERROR_CODE errorCode = THEKOGANS_STREAM_SOCKET_ERROR_CODE;
                if (errorCode != WSA_IO_PENDING) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (errorCode);
                }
            }
            overlapped.release ();
        }

        void TCPSocket::PostAsyncWrite (
                const void *buffer,
                std::size_t count,
                bool useGetBuffer) {
            AsyncInfo::ReadWriteOverlapped::UniquePtr overlapped (
                new AsyncInfo::ReadWriteOverlapped (*this, buffer, count, useGetBuffer));
            if (WSASend ((THEKOGANS_STREAM_SOCKET)handle, &overlapped->wsaBuf, 1, 0, 0,
                    overlapped.get (), 0) == THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_ERROR_CODE errorCode = THEKOGANS_STREAM_SOCKET_ERROR_CODE;
                if (errorCode != WSA_IO_PENDING) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (errorCode);
                }
            }
            overlapped.release ();
        }

        void TCPSocket::PostAsyncAccept () {
            AcceptOverlapped::UniquePtr overlapped (
                new AcceptOverlapped (*this, GetFamily (), GetType (), GetProtocol ()));
            if (!WindowsFunctions::Instance ().AcceptEx (
                    (THEKOGANS_STREAM_SOCKET)handle,
                    overlapped->connection,
                    overlapped->acceptBuffer, 0, 128, 128,
                    &overlapped->bytesReceived, overlapped.get ())) {
                THEKOGANS_UTIL_ERROR_CODE errorCode = THEKOGANS_STREAM_SOCKET_ERROR_CODE;
                if (errorCode != WSA_IO_PENDING) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (errorCode);
                }
            }
            overlapped.release ();
        }

        void TCPSocket::HandleOverlapped (AsyncInfo::Overlapped &overlapped) throw () {
            if (overlapped.event == AsyncInfo::EventConnect) {
                THEKOGANS_UTIL_TRY {
                    PostAsyncRead ();
                    UpdateConnectContext ();
                    asyncInfo->eventSink.HandleTCPSocketConnected (*this);
                }
                THEKOGANS_UTIL_CATCH (util::Exception) {
                    THEKOGANS_UTIL_EXCEPTION_NOTE_LOCATION (exception);
                    asyncInfo->eventSink.HandleStreamError (*this, exception);
                }
            }
            else if (overlapped.event == AsyncInfo::EventDisconnect) {
                asyncInfo->eventSink.HandleStreamDisconnect (*this);
            }
            else if (overlapped.event == AsyncInfo::EventRead) {
                THEKOGANS_UTIL_TRY {
                    AsyncInfo::ReadWriteOverlapped &readWriteOverlapped =
                        (AsyncInfo::ReadWriteOverlapped &)overlapped;
                    if (readWriteOverlapped.buffer.get () == 0) {
                        std::size_t bufferLength = GetDataAvailable ();
                        if (bufferLength != 0) {
                            readWriteOverlapped.buffer =
                                asyncInfo->eventSink.GetBuffer (
                                    *this, util::HostEndian, bufferLength);
                            readWriteOverlapped.buffer->AdvanceWriteOffset (
                                Read (readWriteOverlapped.buffer->GetWritePtr (), bufferLength));
                        }
                    }
                    if (readWriteOverlapped.buffer.get () != 0 &&
                            !readWriteOverlapped.buffer->IsEmpty ()) {
                        PostAsyncRead ();
                        asyncInfo->eventSink.HandleStreamRead (*this,
                            std::move (readWriteOverlapped.buffer));
                    }
                    else {
                        asyncInfo->eventSink.HandleStreamDisconnect (*this);
                    }
                }
                THEKOGANS_UTIL_CATCH (util::Exception) {
                    THEKOGANS_UTIL_EXCEPTION_NOTE_LOCATION (exception);
                    asyncInfo->eventSink.HandleStreamError (*this, exception);
                }
            }
            else if (overlapped.event == AsyncInfo::EventWrite) {
                AsyncInfo::ReadWriteOverlapped &readWriteOverlapped =
                    (AsyncInfo::ReadWriteOverlapped &)overlapped;
                assert (readWriteOverlapped.buffer->IsEmpty ());
                asyncInfo->eventSink.HandleStreamWrite (
                    *this, std::move (readWriteOverlapped.buffer));
            }
        }
    #else // defined (TOOLCHAIN_OS_Windows)
        void TCPSocket::HandleAsyncEvent (util::ui32 event) throw () {
            if (event == AsyncInfo::EventConnect) {
                THEKOGANS_UTIL_TRY {
                    asyncInfo->DeleteStreamForEvents (AsyncInfo::EventConnect);
                    asyncInfo->eventSink.HandleTCPSocketConnected (*this);
                }
                THEKOGANS_UTIL_CATCH (util::Exception) {
                    THEKOGANS_UTIL_EXCEPTION_NOTE_LOCATION (exception);
                    asyncInfo->eventSink.HandleStreamError (*this, exception);
                }
            }
            else if (event == AsyncInfo::EventDisconnect) {
                asyncInfo->eventSink.HandleStreamDisconnect (*this);
            }
            else if (event == AsyncInfo::EventRead) {
                THEKOGANS_UTIL_TRY {
                    std::size_t bufferLength = GetDataAvailable ();
                    if (bufferLength != 0) {
                        util::Buffer buffer =
                            asyncInfo->eventSink.GetBuffer (
                                *this, util::HostEndian, bufferLength);
                        if (buffer.AdvanceWriteOffset (Read (buffer.GetWritePtr (), bufferLength)) > 0) {
                            asyncInfo->eventSink.HandleStreamRead (*this, std::move (buffer));
                        }
                    }
                    else {
                        asyncInfo->eventSink.HandleStreamDisconnect (*this);
                    }
                }
                THEKOGANS_UTIL_CATCH (util::Exception) {
                    THEKOGANS_UTIL_EXCEPTION_NOTE_LOCATION (exception);
                    asyncInfo->eventSink.HandleStreamError (*this, exception);
                }
            }
            else if (event == AsyncInfo::EventWrite) {
                asyncInfo->WriteBuffers ();
            }
        }
    #endif // defined (TOOLCHAIN_OS_Windows)

    } // namespace stream
} // namespace thekogans
