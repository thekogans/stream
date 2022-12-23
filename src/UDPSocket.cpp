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
#if defined (TOOLCHAIN_OS_Windows)
    #if !defined (_WINDOWS_)
        #if !defined (WIN32_LEAN_AND_MEAN)
            #define WIN32_LEAN_AND_MEAN
        #endif // !defined (WIN32_LEAN_AND_MEAN)
        #if !defined (NOMINMAX)
            #define NOMINMAX
        #endif // !defined (NOMINMAX)
        #include <windows.h.>
    #endif // !defined (_WINDOWS_)
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <ws2ipdef.h>
    #include <iphlpapi.h>
#else // defined (TOOLCHAIN_OS_Windows)
    #include <ifaddrs.h>
    #include <net/if.h>
    #if defined (TOOLCHAIN_OS_OSX)
        #define __APPLE_USE_RFC_3542
    #endif // defined (TOOLCHAIN_OS_OSX)
    #include <netinet/in.h>
#endif // defined (TOOLCHAIN_OS_Windows)
#include <cassert>
#include "thekogans/util/Exception.h"
#include "thekogans/stream/AsyncIoEventQueue.h"
#include "thekogans/stream/MsgHdr.h"
#include "thekogans/stream/UDPSocket.h"

namespace thekogans {
    namespace stream {

        THEKOGANS_UTIL_IMPLEMENT_HEAP_WITH_LOCK (UDPSocket, util::SpinLock)

    #if defined (TOOLCHAIN_OS_Windows)
        namespace {
            struct WindowsFunctions : public util::Singleton<WindowsFunctions, util::SpinLock> {
                LPFN_WSARECVMSG WSARecvMsg;
                LPFN_WSASENDMSG WSASendMsg;

                WindowsFunctions () :
                        WSARecvMsg (0),
                        WSASendMsg (0) {
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
                        GUID GuidWSARecvMsg = WSAID_WSARECVMSG;
                        DWORD bytesReturned = 0;
                        if (WSAIoctl (socket.handle,
                                SIO_GET_EXTENSION_FUNCTION_POINTER,
                                &GuidWSARecvMsg, sizeof (GuidWSARecvMsg),
                                &WSARecvMsg, sizeof (WSARecvMsg),
                                &bytesReturned, 0, 0) == THEKOGANS_STREAM_SOCKET_ERROR) {
                            THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                                THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                        }
                    }
                    {
                        GUID GuidWSASendMsg = WSAID_WSASENDMSG;
                        DWORD bytesReturned = 0;
                        if (WSAIoctl (socket.handle,
                                SIO_GET_EXTENSION_FUNCTION_POINTER,
                                &GuidWSASendMsg, sizeof (GuidWSASendMsg),
                                &WSASendMsg, sizeof (WSASendMsg),
                                &bytesReturned, 0, 0) == THEKOGANS_STREAM_SOCKET_ERROR) {
                            THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                                THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                        }
                    }
                }
            };
        }
    #endif // defined (TOOLCHAIN_OS_Windows)

        UDPSocket::UDPSocket (const Address &address) :
                Socket (address.GetFamily (), SOCK_DGRAM, 0) {
            Bind (address);
        }

        namespace {
            /// \struct UDPSocket::ReadFromWriteToOverlapped UDPSocket.h thekogans/stream/UDPSocket.h
            ///
            /// \brief
            /// ReadFromWriteToOverlapped is a helper class. It reduces code clutter and
            /// makes instantiating Overlapped used by \see{UDPSocket::ReadFrom} and
            /// \see{UDPSocket::WriteTo} easier.
            struct ReadFromWriteToOverlapped : public Overlapped {
                /// \brief
                /// Declare \see{RefCounted} pointers.
                THEKOGANS_UTIL_DECLARE_REF_COUNTED_POINTERS (ReadFromWriteToOverlapped)

                /// \brief
                /// ReadFromWriteToOverlapped has a private heap to help with memory
                /// management, performance, and global heap fragmentation.
                THEKOGANS_UTIL_DECLARE_HEAP_WITH_LOCK (ReadFromWriteToOverlapped, util::SpinLock)

                /// \brief
                /// Buffer used by UDPSocket::ReadFrom/WriteTo.
                util::Buffer buffer;
                /// \brief
                /// Address used by UDPSocket::ReadFrom/WriteTo.
                Address address;
                /// \brief
                /// WSARecvFrom/SendTo buffer.
                WSABUF wsaBuf;
                /// \brief
                /// WSARecvFrom/SendTo flags.
                DWORD flags;

                /// \brief
                /// ctor.
                /// \param[in] count Length of buffer to allocate for reading.
                ReadFromWriteToOverlapped (std::size_t count);
                /// \brief
                /// ctor.
                /// \param[in] stream Stream that created this ReadFromWriteToOverlapped.
                /// \param[in] buffer_ Buffer to write.
                /// \param[in] count Lenght of buffer.
                /// \param[in] address_ Used by \see{UDPSocket::PostAsyncWriteTo}.
                /// \param[in] useGetBuffer If true, call \see{AsyncIoEventSink::GetBuffer}
                ReadFromWriteToOverlapped (
                    UDPSocket &udpSocket,
                    const void *buffer_,
                    std::size_t count,
                    const Address &address_,
                    bool useGetBuffer = true);
                /// \brief
                /// ctor.
                /// \param[in] buffer_ Buffer to write.
                /// \param[in] address_ Used by \see{UDPSocket::PostAsyncWriteTo}.
                ReadFromWriteToOverlapped (
                        util::Buffer buffer_,
                        const Address &address_) :
                        Overlapped (Stream::EventUDPSocketWriteTo),
                        buffer (std::move (buffer_)),
                        address (address_),
                        flags (0) {
                    wsaBuf.len = (ULONG)buffer.GetDataAvailableForReading ();
                    wsaBuf.buf = (char *)buffer.GetReadPtr ();
                }

                /// \brief
                /// Called by \see{AsyncIoEventQueue::WaitForEvents} to allow
                /// the ReadFromWriteToOverlapped to perform post op housekeeping.
                virtual bool Epilog (Stream::SharedPtr /*stream*/) throw ();

                /// \brief
                /// ReadFromWriteToOverlapped is neither copy constructable, nor assignable.
                THEKOGANS_STREAM_DISALLOW_COPY_AND_ASSIGN (ReadFromWriteToOverlapped)
            };
        }

        std::size_t UDPSocket::ReadFrom (
                void *buffer,
                std::size_t count,
                Address &address) {
            if ((buffer != 0 && count > 0) || IsAsync ()) {
            #if defined (TOOLCHAIN_OS_Windows)
                DWORD numberOfBytesRecvd = 0;
                if (IsAsync ()) {
                    THEKOGANS_UTIL_TRY {
                        PostAsyncReadFrom ();
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
                    WSABUF wsaBuf = {(ULONG)count, (char *)buffer};
                    DWORD flags = 0;
                    if (WSARecvFrom ((THEKOGANS_STREAM_SOCKET)handle, &wsaBuf,
                            1, &numberOfBytesRecvd, &flags, &address.address,
                            &address.length, 0, 0) == THEKOGANS_STREAM_SOCKET_ERROR) {
                        THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                            THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                    }
                }
                return numberOfBytesRecvd;
            #else // defined (TOOLCHAIN_OS_Windows)
                ssize_t countRead = 0;
                if (IsAsync ()) {
                    THEKOGANS_UTIL_TRY {
                        SetInOverlapped (std::unique_ptr<Overlapped> (new ReadFromWriteToOverlapped (bufferLength)));
                    }
                    THEKOGANS_UTIL_CATCH (util::Exception) {
                        THEKOGANS_UTIL_EXCEPTION_NOTE_LOCATION (exception);
                        util::Producer<StreamEvents>::Produce (
                            std::bind (
                                &StreamEvents::OnStreamError,
                                std::placeholders::_1,
                                Stream::SharedPtr (this),
                                exception));
                    }
                }
                else {
                    countRead = recvfrom (handle, (char *)buffer,
                        count, 0, &address.address, &address.length);
                    if (countRead == THEKOGANS_STREAM_SOCKET_ERROR) {
                        THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                            THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                    }
                }
                return (std::size_t)countRead;
            #endif // defined (TOOLCHAIN_OS_Windows)
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        std::size_t UDPSocket::WriteTo (
                const void *buffer,
                std::size_t count,
                const Address &address) {
            if (buffer != 0 && count > 0 && address != Address::Empty) {
            #if defined (TOOLCHAIN_OS_Windows)
                DWORD numberOfBytesSent = 0;
                if (IsAsync ()) {
                    THEKOGANS_UTIL_TRY {
                        PostAsyncWriteTo (buffer, count, address);
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
                    WSABUF wsaBuf = {(ULONG)count, (char *)buffer};
                    DWORD flags = 0;
                    if (WSASendTo ((THEKOGANS_STREAM_SOCKET)handle, &wsaBuf,
                            1, &numberOfBytesSent, flags, &address.address,
                            address.length, 0, 0) == THEKOGANS_STREAM_SOCKET_ERROR) {
                        THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                            THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                    }
                }
                return numberOfBytesSent;
            #else // defined (TOOLCHAIN_OS_Windows)
                ssize_t countWritten = 0;
                if (IsAsync ()) {
                    EnqOverlappedBack (
                        std::unique_ptr<Overlapped> (
                            new WriteToOverlapped (buffer, count, address)));
                }
                else {
                    countWritten = sendto (handle, (const char *)buffer,
                        count, 0, &address.address, address.length);
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

        void UDPSocket::WriteBufferTo (
                util::Buffer buffer,
                const Address &address) {
            if (!buffer.IsEmpty () && address != Address::Empty) {
                if (IsAsync ()) {
                #if defined (TOOLCHAIN_OS_Windows)
                    ReadFromWriteToOverlapped::SharedPtr overlapped (
                        new ReadFromWriteToOverlapped (*this, std::move (buffer), address));
                    if (WSASendTo ((THEKOGANS_STREAM_SOCKET)handle,
                            &overlapped->wsaBuf, 1, 0,
                            overlapped->flags,
                            &overlapped->address.address,
                            overlapped->address.length,
                            overlapped.get (), 0) == THEKOGANS_STREAM_SOCKET_ERROR) {
                        THEKOGANS_UTIL_ERROR_CODE errorCode = THEKOGANS_STREAM_SOCKET_ERROR_CODE;
                        if (errorCode != WSA_IO_PENDING) {
                            Produce (
                                std::bind (
                                    &StreamEvents::OnStreamError,
                                    std::placeholders::_1,
                                    SharedPtr (this),
                                    THEKOGANS_UTIL_ERROR_CODE_EXCEPTION (errorCode)));
                            return;
                        }
                    }
                    overlapped.Release ();
                #else // defined (TOOLCHAIN_OS_Windows)
                    EnqOverlappedBack (
                        std::unique_ptr<Overlapped> (
                            new WriteToOverlapped (
                                std::move (buffer), address)));
                #endif // defined (TOOLCHAIN_OS_Windows)
                }
                else {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "%s", "WriteBufferTo is called on a blocking socket.");
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        namespace {
            /// \struct UDPSocket::ReadMsgWriteMsgOverlapped UDPSocket.h thekogans/stream/UDPSocket.h
            ///
            /// \brief
            /// ReadMsgWriteMsgOverlapped is a helper class. It reduces code clutter and
            /// makes instantiating Overlapped used by \see{UDPSocket::PostAsyncReadMsg}
            /// easier.
            struct ReadMsgWriteMsgOverlapped : public Overlapped {
                /// \brief
                /// Declare \see{RefCounted} pointers.
                THEKOGANS_UTIL_DECLARE_REF_COUNTED_POINTERS (ReadMsgWriteMsgOverlapped)

                /// \brief
                /// ReadMsgWriteMsgOverlapped has a private heap to help with memory
                /// management, performance, and global heap fragmentation.
                THEKOGANS_UTIL_DECLARE_HEAP_WITH_LOCK (ReadMsgWriteMsgOverlapped, util::SpinLock)

                /// \brief
                /// Buffer used by Stream::Read/Write.
                util::Buffer buffer;
                /// \brief
                /// Address from which the message was sent.
                Address from;
                /// \brief
                /// Address to which the message is sent.
                Address to;
                /// \brief
                /// Used by WSA[Recv | Send]Msg.
                MsgHdr msgHdr;

                /// \brief
                /// ctor.
                /// \param[in] count Length of buffer to allocate for reading.
                ReadMsgWriteMsgOverlapped (std::size_t count);
                /// \brief
                /// ctor.
                /// \param[in] buffer Buffer to write.
                /// \param[in] count Lenght of buffer.
                /// \param[in] from Used by \see{UDPSocket::PostAsyncWriteMsg}.
                /// \param[in] to Used by \see{UDPSocket::PostAsyncWriteMsg}.
                ReadMsgWriteMsgOverlapped (
                    const void *buffer_,
                    std::size_t count,
                    const Address &from_,
                    const Address &to_);
                /// \brief
                /// ctor.
                /// \param[in] stream Stream that created this WriteMsgOverlapped.
                /// \param[in] buffer Buffer to write.
                /// \param[in] from Used by \see{UDPSocket::PostAsyncWriteMsg}.
                /// \param[in] to Used by \see{UDPSocket::PostAsyncWriteMsg}.
                ReadMsgWriteMsgOverlapped (
                    util::Buffer buffer_,
                    const Address &from_,
                    const Address &to_) :
                    Overlapped (Stream::EventUDPSocketWriteMsg),
                    buffer (std::move (buffer_)),
                    from (from_),
                    to (to_),
                    msgHdr (
                        buffer.GetReadPtr (),
                        buffer.GetDataAvailableForReading (),
                        from,
                        to) {}

                /// \brief
                /// Called by \see{AsyncIoEventQueue::WaitForEvents} to allow
                /// the ReadMsgWriteMsgOverlapped to perform post op housekeeping.
                virtual bool Epilog (Stream::SharedPtr /*stream*/) throw ();

                /// \brief
                /// ReadMsgWriteMsgOverlapped is neither copy constructable, nor assignable.
                THEKOGANS_STREAM_DISALLOW_COPY_AND_ASSIGN (ReadMsgWriteMsgOverlapped)
            };
        }

        std::size_t UDPSocket::ReadMsg (
                void *buffer,
                std::size_t count,
                Address &from,
                Address &to) {
            if (buffer != 0 && count > 0) {
            #if defined (TOOLCHAIN_OS_Windows)
                MsgHdr msgHdr (buffer, count, from);
                DWORD numberOfBytesRecvd = 0;
                if (WindowsFunctions::Instance ().WSARecvMsg (
                        (THEKOGANS_STREAM_SOCKET)handle, &msgHdr,
                        &numberOfBytesRecvd, 0, 0) == THEKOGANS_STREAM_SOCKET_ERROR) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                }
                if (from.GetFamily () == AF_INET) {
                    from.length = sizeof (sockaddr_in);
                }
                else if (from.GetFamily () == AF_INET6) {
                    from.length = sizeof (sockaddr_in6);
                }
                to = msgHdr.GetToAddress (GetHostAddress ().GetPort ());
                return numberOfBytesRecvd;
            #else // defined (TOOLCHAIN_OS_Windows)
                MsgHdr msgHdr (buffer, count, from);
                ssize_t countRead = recvmsg (handle, &msgHdr, 0);
                if (countRead == THEKOGANS_STREAM_SOCKET_ERROR) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                }
                if (from.GetFamily () == AF_INET) {
                    from.length = sizeof (sockaddr_in);
                }
                else if (from.GetFamily () == AF_INET6) {
                    from.length = sizeof (sockaddr_in6);
                }
                else if (from.GetFamily () == AF_LOCAL) {
                    from.length = sizeof (sockaddr_un);
                }
                to = msgHdr.GetToAddress (GetHostAddress ().GetPort ());
                return (std::size_t)countRead;
            #endif // defined (TOOLCHAIN_OS_Windows)
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        std::size_t UDPSocket::WriteMsg (
                const void *buffer,
                std::size_t count,
                const Address &from,
                const Address &to) {
            if (buffer != 0 && count > 0 &&
                    from != Address::Empty && to != Address::Empty) {
            #if defined (TOOLCHAIN_OS_Windows)
                DWORD numberOfBytesSent = 0;
                if (IsAsync ()) {
                    THEKOGANS_UTIL_TRY {
                        PostAsyncWriteMsg (buffer, count, from, to);
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
                    MsgHdr msgHdr (buffer, count, from, to);
                    if (WindowsFunctions::Instance ().WSASendMsg (
                            (THEKOGANS_STREAM_SOCKET)handle, &msgHdr, 0,
                            &numberOfBytesSent, 0, 0) == THEKOGANS_STREAM_SOCKET_ERROR) {
                        THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                            THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                    }
                }
                return numberOfBytesSent;
            #else // defined (TOOLCHAIN_OS_Windows)
                ssize_t countWritten = 0;
                if (IsAsync ()) {
                    EnqOverlappedBack (
                        std::unique_ptr<Overlapped> (
                            new WriteMsgOverlapped (
                                buffer, count, from, to)));
                }
                else {
                    MsgHdr msgHdr (buffer, count, from, to);
                    countWritten = sendmsg (handle, &msgHdr, 0);
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

        void UDPSocket::WriteBufferMsg (
                util::Buffer buffer,
                const Address &from,
                const Address &to) {
            if (!buffer.IsEmpty () &&
                    from != Address::Empty && to != Address::Empty) {
                if (IsAsync ()) {
                #if defined (TOOLCHAIN_OS_Windows)
                    ReadMsgWriteMsgOverlapped::SharedPtr overlapped (
                        new ReadMsgWriteMsgOverlapped (*this, std::move (buffer), from, to));
                    if (WindowsFunctions::Instance ().WSASendMsg (
                            (THEKOGANS_STREAM_SOCKET)handle,
                            &overlapped->msgHdr, 0, 0,
                            overlapped.get (), 0) == THEKOGANS_STREAM_SOCKET_ERROR) {
                        THEKOGANS_UTIL_ERROR_CODE errorCode = THEKOGANS_STREAM_SOCKET_ERROR_CODE;
                        if (errorCode != WSA_IO_PENDING) {
                            Produce (
                                std::bind (
                                    &StreamEvents::OnStreamError,
                                    std::placeholders::_1,
                                    SharedPtr (this),
                                    THEKOGANS_UTIL_ERROR_CODE_EXCEPTION (errorCode)));
                            return;
                        }
                    }
                    overlapped.Release ();
                #else // defined (TOOLCHAIN_OS_Windows)
                    EnqOverlappedBack (
                        std::unique_ptr<Overlapped> (
                            new WriteMsgOverlapped (
                                std::move (buffer), from, to)));
                #endif // defined (TOOLCHAIN_OS_Windows)
                }
                else {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "%s", "WriteBufferMsg is called on a blocking socket.");
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        bool UDPSocket::IsBroadcast () const {
            int arg = 0;
            socklen_t length = sizeof (arg);
            if (getsockopt ((THEKOGANS_STREAM_SOCKET)handle, SOL_SOCKET,
                    SO_BROADCAST, (char *)&arg, &length) == THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
            return arg == 1;
        }

        void UDPSocket::SetBroadcast (bool broadcast) {
            u_long arg = broadcast ? 1 : 0;
            if (setsockopt ((THEKOGANS_STREAM_SOCKET)handle, SOL_SOCKET,
                    SO_BROADCAST, (const char *)&arg, sizeof (arg)) == THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
        }

        bool UDPSocket::IsRecvPktInfo () const {
            int level;
            int optionName;
            util::ui16 family = GetFamily ();
            if (family == AF_INET) {
                level = IPPROTO_IP;
                optionName = IP_PKTINFO;
            }
            else if (family == AF_INET6) {
                level = IPPROTO_IPV6;
            #if defined (TOOLCHAIN_OS_Linux)
                optionName = IPV6_RECVPKTINFO;
            #else // defined (TOOLCHAIN_OS_Linux)
                optionName = IPV6_PKTINFO;
            #endif // defined (TOOLCHAIN_OS_Linux)
            }
            else {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "Unknown family: %s (%u)",
                    Address::FamilyToString (family).c_str (), family);
            }
            u_long arg = 0;
            socklen_t length = sizeof (arg);
            if (getsockopt ((THEKOGANS_STREAM_SOCKET)handle, level,
                    optionName, (char *)&arg, &length) == THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
            return arg == 1;
        }

        void UDPSocket::SetRecvPktInfo (bool recvPktInfo) {
            int level;
            int optionName;
            util::ui16 family = GetFamily ();
            if (family == AF_INET) {
                level = IPPROTO_IP;
                optionName = IP_PKTINFO;
            }
            else if (family == AF_INET6) {
                level = IPPROTO_IPV6;
            #if defined (TOOLCHAIN_OS_Linux)
                optionName = IPV6_RECVPKTINFO;
            #else // defined (TOOLCHAIN_OS_Linux)
                optionName = IPV6_PKTINFO;
            #endif // defined (TOOLCHAIN_OS_Linux)
            }
            else {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "Unknown family: %s (%u)",
                    Address::FamilyToString (family).c_str (), family);
            }
            u_long arg = recvPktInfo ? 1 : 0;
            if (setsockopt ((THEKOGANS_STREAM_SOCKET)handle, level,
                    optionName, (const char *)&arg, sizeof (arg)) == THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
        }

        #if !defined (IPV6_HDRINCL)
            #define IPV6_HDRINCL 36
        #endif // !defined (IPV6_HDRINCL)

        bool UDPSocket::IsHdrIncl () const {
            int level;
            int optionName;
            util::ui16 family = GetFamily ();
            if (family == AF_INET) {
                level = IPPROTO_IP;
                optionName = IP_HDRINCL;
            }
            else if (family == AF_INET6) {
                level = IPPROTO_IPV6;
                optionName = IPV6_HDRINCL;
            }
            else {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "Unknown family: %s (%u)",
                    Address::FamilyToString (family).c_str (), family);
            }
            u_long arg = 0;
            socklen_t length = sizeof (arg);
            if (getsockopt ((THEKOGANS_STREAM_SOCKET)handle, level,
                    optionName, (char *)&arg, &length) == THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
            return arg == 1;
        }

        void UDPSocket::SetHdrIncl (bool hdrIncl) {
            int level;
            int optionName;
            util::ui16 family = GetFamily ();
            if (family == AF_INET) {
                level = IPPROTO_IP;
                optionName = IP_HDRINCL;
            }
            else if (family == AF_INET6) {
                level = IPPROTO_IPV6;
                optionName = IPV6_HDRINCL;
            }
            else {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "Unknown family: %s (%u)",
                    Address::FamilyToString (family).c_str (), family);
            }
            u_long arg = hdrIncl ? 1 : 0;
            if (setsockopt ((THEKOGANS_STREAM_SOCKET)handle, level,
                    optionName, (const char *)&arg, sizeof (arg)) == THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
        }

        bool UDPSocket::IsConnected () const {
            Address address;
            return getpeername ((THEKOGANS_STREAM_SOCKET)handle,
                &address.address, &address.length) != THEKOGANS_STREAM_SOCKET_ERROR;
        }

        void UDPSocket::Connect (const Address &address) {
            if (address != Address::Empty) {
            #if defined (TOOLCHAIN_OS_Windows)
                if (WSAConnect ((THEKOGANS_STREAM_SOCKET)handle, &address.address,
                        address.length, 0, 0, 0, 0) == THEKOGANS_STREAM_SOCKET_ERROR) {
            #else // defined (TOOLCHAIN_OS_Windows)
                if (connect ((THEKOGANS_STREAM_SOCKET)handle, &address.address,
                        address.length) == THEKOGANS_STREAM_SOCKET_ERROR) {
            #endif // defined (TOOLCHAIN_OS_Windows)
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        void UDPSocket::JoinMulticastGroup (
                const Address &address,
                util::ui32 adapter) {
            if (address.GetFamily () == AF_INET) {
                ip_mreq mreq;
                mreq.imr_multiaddr = address.in.sin_addr;
                mreq.imr_interface.s_addr = htonl (adapter);
                if (setsockopt ((THEKOGANS_STREAM_SOCKET)handle, IPPROTO_IP,
                        IP_ADD_MEMBERSHIP, (const char *)&mreq, sizeof (mreq)) != 0) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                }
            }
            else if (address.GetFamily () == AF_INET6) {
                ipv6_mreq mreq;
                mreq.ipv6mr_multiaddr = address.in6.sin6_addr;
                mreq.ipv6mr_interface = adapter;
                if (setsockopt ((THEKOGANS_STREAM_SOCKET)handle, IPPROTO_IPV6,
                        IPV6_JOIN_GROUP, (const char *)&mreq, sizeof (mreq)) != 0) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        void UDPSocket::LeaveMulticastGroup (
                const Address &address,
                util::ui32 adapter) {
            if (address.GetFamily () == AF_INET) {
                ip_mreq mreq;
                mreq.imr_multiaddr = address.in.sin_addr;
                mreq.imr_interface.s_addr = htonl (adapter);
                if (setsockopt ((THEKOGANS_STREAM_SOCKET)handle, IPPROTO_IP,
                        IP_DROP_MEMBERSHIP, (const char *)&mreq, sizeof (mreq)) != 0) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                }
            }
            else if (address.GetFamily () == AF_INET6) {
                ipv6_mreq mreq;
                mreq.ipv6mr_multiaddr = address.in6.sin6_addr;
                mreq.ipv6mr_interface = adapter;
                if (setsockopt ((THEKOGANS_STREAM_SOCKET)handle, IPPROTO_IPV6,
                        IPV6_LEAVE_GROUP, (const char *)&mreq, sizeof (mreq)) != 0) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        util::ui32 UDPSocket::GetMulticastTTL () const {
            int ttl = 0;
            socklen_t length = sizeof (ttl);
            int family = GetFamily ();
            if (family == AF_INET) {
                if (getsockopt ((THEKOGANS_STREAM_SOCKET)handle, IPPROTO_IP,
                        IP_MULTICAST_TTL, (char *)&ttl, &length) != 0) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                }
            }
            else if (family == AF_INET6) {
                if (getsockopt ((THEKOGANS_STREAM_SOCKET)handle, IPPROTO_IPV6,
                        IPV6_MULTICAST_HOPS, (char *)&ttl, &length) != 0) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
            return ttl;
        }

        void UDPSocket::SetMulticastTTL (util::ui32 ttl) {
            int family = GetFamily ();
            if (family == AF_INET) {
                if (setsockopt ((THEKOGANS_STREAM_SOCKET)handle, IPPROTO_IP, IP_MULTICAST_TTL,
                        (const char *)&ttl, sizeof (ttl)) != 0) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                }
            }
            else if (family == AF_INET6) {
                if (setsockopt ((THEKOGANS_STREAM_SOCKET)handle, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
                        (const char *)&ttl, sizeof (ttl)) != 0) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        util::ui32 UDPSocket::GetMulticastSendAdapter () const {
            int adapter = 0;
            socklen_t length = sizeof (adapter);
            int family = GetFamily ();
            if (family == AF_INET) {
                if (getsockopt ((THEKOGANS_STREAM_SOCKET)handle, IPPROTO_IP,
                        IP_MULTICAST_IF, (char *)&adapter, &length) != 0) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                }
            }
            else if (family == AF_INET6) {
                if (getsockopt ((THEKOGANS_STREAM_SOCKET)handle, IPPROTO_IPV6,
                        IPV6_MULTICAST_IF, (char *)&adapter, &length) != 0) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
            return adapter;
        }

        void UDPSocket::SetMulticastSendAdapter (util::ui32 adapter) {
            int family = GetFamily ();
            adapter = htonl (adapter);
            if (family == AF_INET) {
                if (setsockopt ((THEKOGANS_STREAM_SOCKET)handle, IPPROTO_IP, IP_MULTICAST_IF,
                        (const char *)&adapter, sizeof (adapter)) != 0) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                }
            }
            else if (family == AF_INET6) {
                if (setsockopt ((THEKOGANS_STREAM_SOCKET)handle, IPPROTO_IPV6, IPV6_MULTICAST_IF,
                        (const char *)&adapter, sizeof (adapter)) != 0) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        bool UDPSocket::IsMulticastLoopback () const {
            int loopback = 0;
            socklen_t length = sizeof (loopback);
            int family = GetFamily ();
            if (family == AF_INET) {
                if (getsockopt ((THEKOGANS_STREAM_SOCKET)handle, IPPROTO_IP,
                        IP_MULTICAST_LOOP, (char *)&loopback, &length) != 0) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                }
            }
            else if (family == AF_INET6) {
                if (getsockopt ((THEKOGANS_STREAM_SOCKET)handle, IPPROTO_IPV6,
                        IPV6_MULTICAST_LOOP, (char *)&loopback, &length) != 0) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
            return loopback == 1;
        }

        void UDPSocket::SetMulticastLoopback (bool loopback) {
            int family = GetFamily ();
            int value = loopback ? 1 : 0;
            if (family == AF_INET) {
                if (setsockopt ((THEKOGANS_STREAM_SOCKET)handle, IPPROTO_IP, IP_MULTICAST_LOOP,
                        (const char *)&value, sizeof (value)) != 0) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                }
            }
            else if (family == AF_INET6) {
                if (setsockopt ((THEKOGANS_STREAM_SOCKET)handle, IPPROTO_IPV6, IPV6_MULTICAST_LOOP,
                        (const char *)&value, sizeof (value)) != 0) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

    #if defined (TOOLCHAIN_OS_Windows)
        THEKOGANS_UTIL_IMPLEMENT_HEAP_WITH_LOCK (UDPSocket::ReadFromWriteToOverlapped, util::SpinLock)

        UDPSocket::ReadFromWriteToOverlapped::ReadFromWriteToOverlapped (std::size_t count) :
                Overlapped (Stream::EventUDPSocketReadFrom),
                buffer (util::NetworkEndian, count),
                flags (0) {
            wsaBuf.len = (ULONG)buffer.GetDataAvailableForWriting ();
            wsaBuf.buf = (char *)buffer.GetWritePtr ();
        }

        UDPSocket::ReadFromWriteToOverlapped::ReadFromWriteToOverlapped (
                const void *buffer_,
                std::size_t count,
                const Address &address_) :
                Overlapped (Stream::EventUDPSocketWriteTo),
                buffer (
                    util::NetworkEndian,
                    (const util::ui8 *)buffer_,
                    (const util::ui8 *)buffer_ + count),
                address (address_),
                flags (0) {
            wsaBuf.len = (ULONG)buffer.GetDataAvailableForReading ();
            wsaBuf.buf = (char *)buffer.GetReadPtr ();
        }

        void UDPSocket::ReadFromWriteToOverlapped::Epilog (Stream::SharedPtr /*stream*/) throw () {
            switch (event) {
                case Stream::EventReadFrom: {
                    buffer.AdvanceWriteOffset (GetCount ());
                    break;
                }
                case Stream::EventWriteTo: {
                    buffer.AdvanceReadOffset (GetCount ());
                    break;
                }
            }
        }

        THEKOGANS_UTIL_IMPLEMENT_HEAP_WITH_LOCK (UDPSocket::ReadMsgWriteMsgOverlapped, util::SpinLock)

        UDPSocket::ReadMsgWriteMsgOverlapped::ReadMsgWriteMsgOverlapped (std::size_t count) :
            Overlapped (Stream::EventUDPSocketReadMsg),
            buffer (util::NetworkEndian, count),
            msgHdr (
                count > 0 ? buffer.GetWritePtr () : 0,
                count > 0 ? buffer.GetDataAvailableForWriting () : 0,
                from) {}

        UDPSocket::ReadMsgWriteMsgOverlapped::ReadMsgWriteMsgOverlapped (
            const void *buffer_,
            std::size_t count,
            const Address &from_,
            const Address &to_) :
            Overlapped (Stream::EventUDPSocketWriteMsg),
            buffer (
                util::NetworkEndian,
                (const util::ui8 *)buffer_,
                (const util::ui8 *)buffer_ + count),
            from (from_),
            to (to_),
            msgHdr (buffer.GetReadPtr (), buffer.GetDataAvailableForReading (), from, to) {}

        void UDPSocket::ReadMsgWriteMsgOverlapped::Epilog (Stream::SharedPtr stream) throw () {
            switch (event) {
                case Stream::EventReadMsg: {
                    buffer.AdvanceWriteOffset (GetCount ());
                    if (from.GetFamily () == AF_INET) {
                        from.length = sizeof (sockaddr_in);
                    }
                    else if (from.GetFamily () == AF_INET6) {
                        from.length = sizeof (sockaddr_in6);
                    }
                    to = msgHdr.GetToAddress (
                        dynamic_cast<Socket *> (stream.Get ())->GetHostAddress ().GetPort ());
                    break;
                }
                case Stream::EventWriteMsg: {
                    buffer.AdvanceReadOffset (GetCount ());
                    break;
                }
            }
        }

        void UDPSocket::PostAsyncRead () {
        }

        void UDPSocket::PostAsyncWrite (
                const void *buffer,
                std::size_t count) {
            std::unique_ptr<ReadWriteOverlapped> overlapped (
                new ReadWriteOverlapped (buffer, count));
            if (WSASend ((THEKOGANS_STREAM_SOCKET)handle,
                    &overlapped->wsaBuf, 1, 0, 0,
                    overlapped.get (), 0) == THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_ERROR_CODE errorCode = THEKOGANS_STREAM_SOCKET_ERROR_CODE;
                if (errorCode != WSA_IO_PENDING) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (errorCode);
                }
            }
            overlapped.release ();
        }

        void UDPSocket::PostAsyncReadFrom () {
            std::unique_ptr<ReadFromWriteToOverlapped> overlapped (
                new ReadFromWriteToOverlapped (bufferLength));
            if (WSARecvFrom ((THEKOGANS_STREAM_SOCKET)handle,
                    &overlapped->wsaBuf, 1, 0,
                    &overlapped->flags,
                    &overlapped->address.address,
                    &overlapped->address.length,
                    overlapped.get (), 0) == THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_ERROR_CODE errorCode = THEKOGANS_STREAM_SOCKET_ERROR_CODE;
                if (errorCode != WSA_IO_PENDING) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (errorCode);
                }
            }
            overlapped.release ();
        }

        void UDPSocket::PostAsyncWriteTo (
                const void *buffer,
                std::size_t count,
                const Address &address) {
            std::unique_ptr<ReadFromWriteToOverlapped> overlapped (
                new ReadFromWriteToOverlapped (buffer, count, address));
            if (WSASendTo ((THEKOGANS_STREAM_SOCKET)handle,
                    &overlapped->wsaBuf, 1, 0,
                    overlapped->flags,
                    &overlapped->address.address,
                    overlapped->address.length,
                    overlapped.get (), 0) == THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_ERROR_CODE errorCode = THEKOGANS_STREAM_SOCKET_ERROR_CODE;
                if (errorCode != WSA_IO_PENDING) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (errorCode);
                }
            }
            overlapped.release ();
        }

        void UDPSocket::PostAsyncReadMsg () {
            std::unique_ptr<ReadMsgWriteMsgOverlapped> overlapped (
                new ReadMsgWriteMsgOverlapped (bufferLength));
            if (WindowsFunctions::Instance ().WSARecvMsg (
                    (THEKOGANS_STREAM_SOCKET)handle,
                    &overlapped->msgHdr, 0,
                    overlapped.get (), 0) == THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_ERROR_CODE errorCode = THEKOGANS_STREAM_SOCKET_ERROR_CODE;
                if (errorCode != WSA_IO_PENDING) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (errorCode);
                }
            }
            overlapped.release ();
        }

        void UDPSocket::PostAsyncWriteMsg (
                const void *buffer,
                std::size_t count,
                const Address &from,
                const Address &to) {
            std::unique_ptr<ReadMsgWriteMsgOverlapped> overlapped (
                new ReadMsgWriteMsgOverlapped (buffer, count, from, to));
            if (WindowsFunctions::Instance ().WSASendMsg (
                    (THEKOGANS_STREAM_SOCKET)handle,
                    &overlapped->msgHdr, 0, 0,
                    overlapped.get (), 0) == THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_ERROR_CODE errorCode = THEKOGANS_STREAM_SOCKET_ERROR_CODE;
                if (errorCode != WSA_IO_PENDING) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (errorCode);
                }
            }
            overlapped.release ();
        }

        void UDPSocket::HandleOverlapped (Overlapped &overlapped) throw () {
            if (overlapped.event == EventStreamRead) {
                THEKOGANS_UTIL_TRY {
                    PostAsyncRead ();
                    ReadWriteOverlapped &readWriteOverlapped = (ReadWriteOverlapped &)overlapped;
                    if (readWriteOverlapped.buffer.IsEmpty ()) {
                        std::size_t bufferLength = GetDataAvailable ();
                        if (bufferLength != 0) {
                            readWriteOverlapped.buffer = util::Buffer (util::NetworkEndian, bufferLength);
                            readWriteOverlapped.buffer.AdvanceWriteOffset (
                                Read (readWriteOverlapped.buffer.GetWritePtr (), bufferLength));
                        }
                    }
                    if (!readWriteOverlapped.buffer.IsEmpty ()) {
                        Produce (
                            std::bind (
                                &StreamEvents::OnStreamRead,
                                std::placeholders::_1,
                                SharedPtr (this),
                                std::move (readWriteOverlapped.buffer)));
                    }
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
            else if (overlapped.event == EventStreamWrite) {
                ReadWriteOverlapped &readWriteOverlapped = (ReadWriteOverlapped &)overlapped;
                assert (readWriteOverlapped.buffer.IsEmpty ());
                Produce (
                    std::bind (
                        &StreamEvents::OnStreamWrite,
                        std::placeholders::_1,
                        SharedPtr (this),
                        std::move (readWriteOverlapped.buffer)));
            }
            else if (overlapped.event == EventUDPSocketReadFrom) {
                THEKOGANS_UTIL_TRY {
                    PostAsyncReadFrom ();
                    ReadFromWriteToOverlapped &readFromWriteToOverlapped =
                        (ReadFromWriteToOverlapped &)overlapped;
                    if (readFromWriteToOverlapped.buffer.IsEmpty ()) {
                        std::size_t bufferLength = GetDataAvailable ();
                        if (bufferLength != 0) {
                            readFromWriteToOverlapped.buffer = util::Buffer (util::NetworkEndian, bufferLength);
                            readFromWriteToOverlapped.buffer.AdvanceWriteOffset (
                                ReadFrom (
                                    readFromWriteToOverlapped.buffer.GetWritePtr (),
                                    bufferLength,
                                    readFromWriteToOverlapped.address));
                        }
                    }
                    if (!readFromWriteToOverlapped.buffer.IsEmpty ()) {
                        Produce (
                            std::bind (
                                &UDPSocketEvents::OnStreamUDPSocketReadFrom,
                                std::placeholders::_1,
                                SharedPtr (this),
                                std::move (readFromWriteToOverlapped.buffer),
                                readFromWriteToOverlapped.address));
                    }
                }
                THEKOGANS_UTIL_CATCH (util::Exception) {
                    THEKOGANS_UTIL_EXCEPTION_NOTE_LOCATION (exception);
                    Produce (
                        std::bind (
                            &StreamEvents::OnStreamError,
                            std::placeholders::_1,
                            Stream::SharedPtr (this),
                            exception));
                }
            }
            else if (overlapped.event == EventUDPSocketWriteTo) {
                ReadFromWriteToOverlapped &readFromWriteToOverlapped =
                    (ReadFromWriteToOverlapped &)overlapped;
                assert (readFromWriteToOverlapped.buffer.IsEmpty ());
                Produce (
                    std::bind (
                        &UDPSocketEvents::OnStreamUDPSocketWriteTo,
                        std::placeholders::_1,
                        SharedPtr (this),
                        std::move (readFromWriteToOverlapped.buffer),
                        readFromWriteToOverlapped.address));
            }
            else if (overlapped.event == EventUDPSocketReadMsg) {
                THEKOGANS_UTIL_TRY {
                    PostAsyncReadMsg ();
                    ReadMsgWriteMsgOverlapped &readMsgWriteMsgOverlapped =
                        (ReadMsgWriteMsgOverlapped &)overlapped;
                    if (readMsgWriteMsgOverlapped.buffer.IsEmpty ()) {
                        std::size_t bufferLength = GetDataAvailable ();
                        if (bufferLength != 0) {
                            readMsgWriteMsgOverlapped.buffer = util::Buffer (util::NetworkEndian, bufferLength);
                            readMsgWriteMsgOverlapped.buffer.AdvanceWriteOffset (
                                ReadMsg (
                                    readMsgWriteMsgOverlapped.buffer.GetWritePtr (),
                                    bufferLength,
                                    readMsgWriteMsgOverlapped.from,
                                    readMsgWriteMsgOverlapped.to));
                        }
                    }
                    if (!readMsgWriteMsgOverlapped.buffer.IsEmpty ()) {
                        Produce (
                            std::bind (
                                &UDPSocketEvents::OnUDPSocketReadMsg,
                                std::placeholders::_1,
                                SharedPtr (this),
                                std::move (readMsgWriteMsgOverlapped.buffer),
                                readMsgWriteMsgOverlapped.from,
                                readMsgWriteMsgOverlapped.to);
                    }
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
            else if (overlapped.event == EventUDPSocketWriteMsg) {
                ReadMsgWriteMsgOverlapped &readMsgWriteMsgOverlapped =
                    (ReadMsgWriteMsgOverlapped &)overlapped;
                assert (readMsgWriteMsgOverlapped.buffer.IsEmpty ());
                Produce (
                    std::bind (
                        &UDPSocketEvents::OnUDPSocketWriteMsg,
                        std::placeholders::_1,
                        SharedPtr (this),
                        std::move (readMsgWriteMsgOverlapped.buffer),
                        readMsgWriteMsgOverlapped.from,
                        readMsgWriteMsgOverlapped.to);
            }
        }
    #else // defined (TOOLCHAIN_OS_Windows)
        THEKOGANS_UTIL_IMPLEMENT_HEAP_WITH_LOCK (UDPSocket::WriteToOverlapped, util::SpinLock)

        UDPSocket::WriteToOverlapped::WriteToOverlapped (
            const void *buffer_,
            std::size_t count,
            const Address &address_) :
            Overlapped (EventUDPSocketWriteTo),
            buffer (
                util::NetworkEndian,
                (const util::ui8 *)buffer_,
                (const util::ui8 *)buffer_ + count),
            address (address_) {}

        ssize_t UDPSocket::WriteToOverlapped::Prolog (Stream::SharedPtr stream) {
            ssize_t countWritten = sendto (stream->GetHandle (),
                buffer.GetReadPtr (), buffer.GetDataAvailableForReading (), 0,
                &address.address, address.length);
            if (countWritten > 0) {
                buffer.AdvanceReadOffset ((std::size_t)countWritten);
            }
            return countWritten;
        }

        bool UDPSocket::WriteToOverlapped::Epilog (Stream::SharedPtr stream) {
            if (buffer.IsEmpty ()) {
                UDPSocket::SharedPtr udpSocket = util::dynamic_refcounted_sharedptr_cast<UDPSocket> (stream);
                util::Producer<UDPSocketEvents>::SharedPtr (udpSocket.Get ())->Produce (
                    std::bind (
                        &UDPSocketEvents::OnUDPSocketWriteTo,
                        std::placeholders::_1,
                        udpSocket,
                        std::move (buffer),
                        address));
                return true;
            }
            return false;
        }

        THEKOGANS_UTIL_IMPLEMENT_HEAP_WITH_LOCK (UDPSocket::WriteMsgOverlapped, util::SpinLock)

        UDPSocket::WriteMsgOverlapped::WriteMsgOverlapped (
            const void *buffer_,
            std::size_t count,
            const Address &from_,
            const Address &to_) :
            Overlapped (EventUDPSocketWriteMsg),
            buffer (
                util::NetworkEndian,
                (const util::ui8 *)buffer_,
                (const util::ui8 *)buffer_ + count),
            from (from_),
            to (to_) {}

        ssize_t UDPSocket::WriteMsgOverlapped::Prolog (Stream::SharedPtr stream) {
            MsgHdr msgHdr (buffer.GetReadPtr (), buffer.GetDataAvailableForReading (), from, to);
            ssize_t countWritten = sendmsg (stream->GetHandle (), &msgHdr, 0);
            if (countWritten > 0) {
                buffer.AdvanceReadOffset ((std::size_t)countWritten);
            }
            return countWritten;
        }

        bool UDPSocket::WriteMsgOverlapped::Epilog (Stream::SharedPtr stream) {
            if (buffer.IsEmpty ()) {
                UDPSocket::SharedPtr udpSocket = util::dynamic_refcounted_sharedptr_cast<UDPSocket> (stream);
                util::dynamic_refcounted_sharedptr_cast<util::Producer<UDPSocketEvents>> (udpSocket)->Produce (
                    std::bind (
                        &UDPSocketEvents::OnUDPSocketWriteMsg,
                        std::placeholders::_1,
                        udpSocket,
                        std::move (buffer),
                        from,
                        to));
                return true;
            }
            return false;
        }

        void UDPSocket::HandleAsyncEvent (util::ui32 event) throw () {
            if (event == EventStreamRead) {
                THEKOGANS_UTIL_TRY {
                    std::size_t bufferLength = GetDataAvailable ();
                    if (bufferLength != 0) {
                        util::Buffer buffer = util::Buffer (util::NetworkEndian, bufferLength);
                        if (buffer.AdvanceWriteOffset (
                                Read (buffer.GetWritePtr (), bufferLength)) > 0) {
                            util::Producer<StreamEvents>::Produce (
                                std::bind (
                                    &StreamEvents::OnStreamRead,
                                    std::placeholders::_1,
                                    Stream::SharedPtr (this),
                                    std::move (buffer)));
                        }
                    }
                }
                THEKOGANS_UTIL_CATCH (util::Exception) {
                    THEKOGANS_UTIL_EXCEPTION_NOTE_LOCATION (exception);
                    util::Producer<StreamEvents>::Produce (
                        std::bind (
                            &StreamEvents::OnStreamError,
                            std::placeholders::_1,
                            Stream::SharedPtr (this),
                            exception));
                }
            }
            else if (event == EventStreamWrite) {
                PumpAsyncIo ();
            }
            if (event == EventUDPSocketReadFrom) {
                THEKOGANS_UTIL_TRY {
                    std::size_t bufferLength = GetDataAvailable ();
                    if (bufferLength != 0) {
                        util::Buffer buffer = util::Buffer (util::NetworkEndian, bufferLength);
                        Address address;
                        if (buffer.AdvanceWriteOffset (
                                ReadFrom (buffer.GetWritePtr (), bufferLength, address)) > 0) {
                            util::Producer<UDPSocketEvents>::Produce (
                                std::bind (
                                    &UDPSocketEvents::OnUDPSocketReadFrom,
                                    std::placeholders::_1,
                                    SharedPtr (this),
                                    std::move (buffer),
                                    address));
                        }
                    }
                }
                THEKOGANS_UTIL_CATCH (util::Exception) {
                    THEKOGANS_UTIL_EXCEPTION_NOTE_LOCATION (exception);
                    util::Producer<StreamEvents>::Produce (
                        std::bind (
                            &StreamEvents::OnStreamError,
                            std::placeholders::_1,
                            Stream::SharedPtr (this),
                            exception));
                }
            }
            else if (event == EventUDPSocketWriteTo) {
                PumpAsyncIo ();
            }
            else if (event == EventUDPSocketReadMsg) {
                THEKOGANS_UTIL_TRY {
                    std::size_t bufferLength = GetDataAvailable ();
                    if (bufferLength != 0) {
                        util::Buffer buffer (util::NetworkEndian, bufferLength);
                        Address from;
                        Address to;
                        if (buffer.AdvanceWriteOffset (
                                ReadMsg (buffer.GetWritePtr (), bufferLength, from, to)) > 0) {
                            util::Producer<UDPSocketEvents>::Produce (
                                std::bind (
                                    &UDPSocketEvents::OnUDPSocketReadMsg,
                                    std::placeholders::_1,
                                    SharedPtr (this),
                                    std::move (buffer),
                                    from,
                                    to));
                        }
                    }
                }
                THEKOGANS_UTIL_CATCH (util::Exception) {
                    THEKOGANS_UTIL_EXCEPTION_NOTE_LOCATION (exception);
                    util::Producer<StreamEvents>::Produce (
                        std::bind (
                            &StreamEvents::OnStreamError,
                            std::placeholders::_1,
                            Stream::SharedPtr (this),
                            exception));
                }
            }
            else if (event == EventUDPSocketWriteMsg) {
                PumpAsyncIo ();
            }
        }
    #endif // defined (TOOLCHAIN_OS_Windows)

    } // namespace stream
} // namespace thekogans
