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

#include "thekogans/util/Environment.h"
#if !defined (TOOLCHAIN_OS_Windows)
    #include <sys/ioctl.h>
    #include <netinet/tcp.h>
#endif // !defined (TOOLCHAIN_OS_Windows)
#include <cassert>
#include <cstdio>
#include "thekogans/util/Path.h"
#include "thekogans/util/Exception.h"
#include "thekogans/util/LoggerMgr.h"
#include "thekogans/stream/TCPSocket.h"

namespace thekogans {
    namespace stream {

        THEKOGANS_STREAM_IMPLEMENT_STREAM (TCPSocket)

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

        TCPSocket::TCPSocket (
                const Address &address,
                bool reuseAddress,
                util::i32 maxPendingConnections) :
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

        namespace {
            struct ConnectOverlapped : public Overlapped {
                THEKOGANS_STREAM_DECLARE_OVERLAPPED (ConnectOverlapped)

                Address address;

                ConnectOverlapped (const Address &address_) :
                    address (address_) {}

                virtual ssize_t Prolog (Stream &stream) throw () override {
                #if defined (TOOLCHAIN_OS_Windows)
                    if (GetError () != ERROR_SUCCESS) {
                        return -1;
                    }
                    if (setsockopt (
                            (THEKOGANS_STREAM_SOCKET)stream.GetHandle (),
                            SOL_SOCKET,
                            SO_UPDATE_CONNECT_CONTEXT,
                            0,
                            0) == THEKOGANS_STREAM_SOCKET_ERROR) {
                        SetError (THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                        return -1;
                    }
                #endif // defined (TOOLCHAIN_OS_Windows)
                    return 1;
                }
            };

            THEKOGANS_STREAM_IMPLEMENT_OVERLAPPED (ConnectOverlapped)
        }

        void TCPSocket::Connect (const Address &address) {
        #if defined (TOOLCHAIN_OS_Windows)
            // Asshole M$ strikes again. Wasted a significant
            // portion of my life chasing a bug that wound up
            // being that ConnectEx needs the socket to be
            // explicitly bound.
            if (!IsBound ()) {
                Bind (Address::Any (0, address.GetFamily ()));
            }
            ConnectOverlapped::UniquePtr overlapped (new ConnectOverlapped (address));
            if (!WindowsFunctions::Instance ().ConnectEx (
                    (THEKOGANS_STREAM_SOCKET)handle,
                    &overlapped->address.address,
                    overlapped->address.length,
                    0,
                    0,
                    0,
                    overlapped.get ())) {
                THEKOGANS_UTIL_ERROR_CODE errorCode = THEKOGANS_STREAM_SOCKET_ERROR_CODE;
                if (errorCode != WSA_IO_PENDING) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (errorCode);
                }
            }
            overlapped.release ();
        #else // defined (TOOLCHAIN_OS_Windows)
            // NOTE: Because of the way Stream is designed it's
            // theoretically possible to create a TCPSocket and call
            // Socket::Write without calling TCPSocket::Connect
            // first. Since the socket has not connected yet it will
            // just sit there waiting for write to be ready which
            // will never come. Always call Connect first.
            EnqOverlapped (Overlapped::UniquePtr (new ConnectOverlapped (address)), out);
            if (connect ((THEKOGANS_STREAM_SOCKET)handle, &address.address, address.length) ==
                    THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_ERROR_CODE errorCode = THEKOGANS_STREAM_SOCKET_ERROR_CODE;
                if (errorCode != EINPROGRESS) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (errorCode);
                }
            }
        #endif // defined (TOOLCHAIN_OS_Windows)
        }

    #if defined (TOOLCHAIN_OS_Windows)
        namespace {
            struct DisconnectOverlapped : public Overlapped {
                THEKOGANS_STREAM_DECLARE_OVERLAPPED (DisconnectOverlapped)

                DisconnectOverlapped () {}
                virtual ssize_t Prolog (Stream & /*stream*/) throw () override {
                    return GetError () == ERROR_SUCCESS ? 1 : -1;
                }
            };

            THEKOGANS_STREAM_IMPLEMENT_OVERLAPPED (DisconnectOverlapped)
        }

        void TCPSocket::Disconnect (bool reuseSocket) {
            Overlapped::UniquePtr overlapped (new DisconnectOverlapped);
            if (!WindowsFunctions::Instance ().DisconnectEx (
                    (THEKOGANS_STREAM_SOCKET)handle,
                    overlapped.get (),
                    reuseSocket ? TF_REUSE_SOCKET : 0,
                    0)) {
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

        struct AcceptOverlapped : public Overlapped {
            THEKOGANS_STREAM_DECLARE_OVERLAPPED (AcceptOverlapped)

        #if defined (TOOLCHAIN_OS_Windows)
            char acceptBuffer[256];
            DWORD bytesReceived;
        #endif // defined (TOOLCHAIN_OS_Windows)
            TCPSocket::SharedPtr connection;

        #if defined (TOOLCHAIN_OS_Windows)
            AcceptOverlapped (
                int family,
                int type,
                int protocol) :
                connection (
                    new TCPSocket (
                        (THEKOGANS_UTIL_HANDLE)WSASocketW (
                            family,
                            type,
                            protocol,
                            0,
                            0,
                            WSA_FLAG_OVERLAPPED))),
                bytesReceived (0) {}
        #else // defined (TOOLCHAIN_OS_Windows)
            AcceptOverlapped () {}
        #endif // defined (TOOLCHAIN_OS_Windows)

            virtual ssize_t Prolog (Stream &stream) throw () override {
            #if defined (TOOLCHAIN_OS_Windows)
                if (GetError () != ERROR_SUCCESS) {
                    return -1;
                }
                THEKOGANS_STREAM_SOCKET handle = (THEKOGANS_STREAM_SOCKET)stream.GetHandle ();
                if (setsockopt (
                        (THEKOGANS_STREAM_SOCKET)connection->GetHandle (),
                        SOL_SOCKET,
                        SO_UPDATE_ACCEPT_CONTEXT,
                        (char *)&handle,
                        sizeof (THEKOGANS_STREAM_SOCKET)) == THEKOGANS_STREAM_SOCKET_ERROR) {
                    SetError (THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                    return -1;
                }
            #else // defined (TOOLCHAIN_OS_Windows)
                THEKOGANS_STREAM_SOCKET socket = accept ((THEKOGANS_STREAM_SOCKET)stream.GetHandle (), 0, 0);
                if (socket == THEKOGANS_STREAM_INVALID_SOCKET) {
                    SetError (THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                    return -1;
                }
                connection.Reset (new TCPSocket ((THEKOGANS_UTIL_HANDLE)socket));
            #endif // defined (TOOLCHAIN_OS_Windows)
                return 1;
            }

            virtual bool Epilog (Stream &stream) throw () override {
                if (stream.IsChainRead ()) {
                    dynamic_cast<TCPSocket *> (&stream)->Accept ();
                }
                return true;
            }
        };

        THEKOGANS_STREAM_IMPLEMENT_OVERLAPPED (AcceptOverlapped)

        void TCPSocket::Accept () {
        #if defined (TOOLCHAIN_OS_Windows)
            AcceptOverlapped::UniquePtr overlapped (
                new AcceptOverlapped (GetFamily (), GetType (), GetProtocol ()));
            if (!WindowsFunctions::Instance ().AcceptEx (
                    (THEKOGANS_STREAM_SOCKET)handle,
                    (THEKOGANS_STREAM_SOCKET)overlapped->connection->GetHandle (),
                    overlapped->acceptBuffer,
                    0,
                    128,
                    128,
                    &overlapped->bytesReceived,
                    overlapped.get ())) {
                THEKOGANS_UTIL_ERROR_CODE errorCode = THEKOGANS_STREAM_SOCKET_ERROR_CODE;
                if (errorCode != WSA_IO_PENDING) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (errorCode);
                }
            }
            overlapped.release ();
        #else // defined (TOOLCHAIN_OS_Windows)
            EnqOverlapped (
                Overlapped::UniquePtr (new AcceptOverlapped),
                in);
        #endif // defined (TOOLCHAIN_OS_Windows)
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
                        const wchar_t *subKey) :
                        key (0) {
                    if (RegOpenKeyExW (root, subKey, 0, KEY_READ, &key) != ERROR_SUCCESS) {
                        THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                            THEKOGANS_UTIL_OS_ERROR_CODE);
                    }
                }
                ~Registry () {
                    RegCloseKey (key);
                }

                DWORD GetDWORD (
                        const wchar_t *valueName,
                        DWORD valueDefault) const {
                    DWORD value = 0;
                    DWORD valueSize = sizeof (DWORD);
                    if (RegQueryValueExW (key, valueName, 0, 0,
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
                        L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters").GetDWORD (
                            L"KeepAliveTime",
                            DEFAULT_KEEPALIVE_TIME);
            }

            u_long GetKeepAliveTimeInterval (util::ui32 interval) {
                return interval != util::UI32_MAX ?
                    interval *= 1000 :
                    Registry (
                        HKEY_LOCAL_MACHINE,
                        L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters").GetDWORD (
                            L"KeepAliveInterval",
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
            }
            if (shutdown ((THEKOGANS_STREAM_SOCKET)handle, how) == THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
        }

        void TCPSocket::HandleOverlapped (Overlapped &overlapped) throw () {
            if (overlapped.GetType () == ConnectOverlapped::TYPE) {
                ConnectOverlapped &connectOverlapped = (ConnectOverlapped &)overlapped;
                util::Producer<TCPSocketEvents>::Produce (
                    std::bind (
                        &TCPSocketEvents::OnTCPSocketConnect,
                        std::placeholders::_1,
                        SharedPtr (this),
                        connectOverlapped.address));
            }
        #if defined (TOOLCHAIN_OS_Windows)
            else if (overlapped.GetType () == DisconnectOverlapped::TYPE) {
                HandleDisconnect ();
            }
        #endif // defined (TOOLCHAIN_OS_Windows)
            else if (overlapped.GetType () == AcceptOverlapped::TYPE) {
                AcceptOverlapped &acceptOverlapped = (AcceptOverlapped &)overlapped;
                util::Producer<TCPSocketEvents>::Produce (
                    std::bind (
                        &TCPSocketEvents::OnTCPSocketAccept,
                        std::placeholders::_1,
                        SharedPtr (this),
                        acceptOverlapped.connection));
            }
            else {
                Socket::HandleOverlapped (overlapped);
            }
        }

    } // namespace stream
} // namespace thekogans
