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
        #include <windows.h>
    #endif // !defined (_WINDOWS_)
    #include <winsock2.h>
#else // defined (TOOLCHAIN_OS_Windows)
    #include <sys/ioctl.h>
    #include <arpa/inet.h>
    #include <net/if.h>
    #include <netinet/in.h>
    #if defined (TOOLCHAIN_OS_Linux)
        #include <stropts.h>
    #endif // defined (TOOLCHAIN_OS_Linux)
#endif // defined (TOOLCHAIN_OS_Windows)
#include <cstdio>
#include "thekogans/util/Flags.h"
#include "thekogans/util/Exception.h"
#include "thekogans/util/LoggerMgr.h"
#include "thekogans/util/StringUtils.h"
#include "thekogans/util/XMLUtils.h"
#include "thekogans/stream/AsyncIoEventSink.h"
#include "thekogans/stream/Socket.h"

namespace thekogans {
    namespace stream {

    #if defined (TOOLCHAIN_OS_Windows)
        namespace {
            // This Windows specific initialization happens during
            // static ctor creation. No throwing here. If WSAStartup
            // fails, the clients will know soon enough when they
            // try to create sockets.
            struct WinSockInit {
                WinSockInit () {
                    WSADATA data;
                    WSAStartup (MAKEWORD (2, 2), &data);
                }
                ~WinSockInit () {
                    WSACleanup ();
                }
            } winSockInit;
        }
    #endif // defined (TOOLCHAIN_OS_Windows)

        const char * const Socket::Context::VALUE_SOCKET = "Socket";
        const char * const Socket::Context::ATTR_FAMILY = "Family";
        const char * const Socket::Context::ATTR_TYPE = "Type";
        const char * const Socket::Context::ATTR_PROTOCOL = "Protocol";

        void Socket::Context::Parse (const pugi::xml_node &node) {
            Stream::Context::Parse (node);
            family = util::stringToi32 (node.attribute (ATTR_FAMILY).value ());
            type = util::stringToi32 (node.attribute (ATTR_TYPE).value ());
            protocol = util::stringToi32 (node.attribute (ATTR_PROTOCOL).value ());
        }

        std::string Socket::Context::ToString (
                std::size_t indentationLevel,
                const char *tagName) const {
            if (tagName != 0) {
                util::Attributes attributes;
                attributes.push_back (util::Attribute (ATTR_STREAM_TYPE, util::Encodestring (VALUE_SOCKET)));
                attributes.push_back (util::Attribute (ATTR_FAMILY, util::i32Tostring (family)));
                attributes.push_back (util::Attribute (ATTR_TYPE, util::i32Tostring (type)));
                attributes.push_back (util::Attribute (ATTR_PROTOCOL, util::i32Tostring (protocol)));
                return util::OpenTag (indentationLevel, tagName, attributes, false, true);
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        Socket::Socket (THEKOGANS_UTIL_HANDLE handle) :
                Stream (handle) {
            if (IsOpen ()) {
            #if defined (TOOLCHAIN_OS_Windows)
                WSAPROTOCOL_INFOW protocolInfo;
                socklen_t length = sizeof (WSAPROTOCOL_INFOW);
                if (getsockopt ((THEKOGANS_STREAM_SOCKET)handle, SOL_SOCKET, SO_PROTOCOL_INFO,
                        (char *)&protocolInfo, &length) == THEKOGANS_STREAM_SOCKET_ERROR) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                }
                family = protocolInfo.iAddressFamily;
                type = protocolInfo.iSocketType;
                protocol = protocolInfo.iProtocol;
            #else // defined (TOOLCHAIN_OS_Windows)
                socklen_t length = sizeof (int);
            #if defined (TOOLCHAIN_OS_Linux)
                if (getsockopt (handle, SOL_SOCKET, SO_DOMAIN, &family, &length) ==
                        THEKOGANS_STREAM_SOCKET_ERROR) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                }
            #elif defined (TOOLCHAIN_OS_OSX)
                // Asshole Apple does not provide a way of getting
                // socket family and protocol. This only works if
                // Bind was called on the handle. If you're not
                // calling this ctor explicitly, you have nothing
                // to worry about as it's only used in two places
                // by thekogans_stream; 1) Stream::StaticInit and
                // 2) TCPSocket::Accept. The first use is just to
                // instantiate a dummy socket, and the second will
                // work correctly as accept will do an implicit bind.
                // If you're calling this ctor explicitly you need to
                // make sure you either; 1) provide valid values or
                // 2) getsockname returns a valid address. Otherwise
                // your socket will return bad information for type
                // (GetType ()) and protocol (GetProtocol ()).
                {
                    Address address;
                    if (getsockname ((THEKOGANS_STREAM_SOCKET)handle, (sockaddr *)&address.storage,
                            &address.length) != THEKOGANS_STREAM_SOCKET_ERROR) {
                        family = address.storage.ss_family;
                    }
                }
            #endif // defined (TOOLCHAIN_OS_Linux)
                if (getsockopt (handle, SOL_SOCKET, SO_TYPE, &type, &length) ==
                        THEKOGANS_STREAM_SOCKET_ERROR) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                }
            #if defined (TOOLCHAIN_OS_Linux)
                if (getsockopt (handle, SOL_SOCKET, SO_PROTOCOL, &protocol, &length) ==
                        THEKOGANS_STREAM_SOCKET_ERROR) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                }
            #elif defined (TOOLCHAIN_OS_OSX)
                protocol =
                    type == SOCK_STREAM ? IPPROTO_TCP :
                    (type == SOCK_DGRAM || type == SOCK_RAW) ? IPPROTO_UDP : 0;
            #endif // defined (TOOLCHAIN_OS_Linux)
            #endif // defined (TOOLCHAIN_OS_Windows)
            }
        }

        Socket::Socket (
                int family_,
                int type_,
                int protocol_) :
            #if defined (TOOLCHAIN_OS_Windows)
                Stream ((THEKOGANS_UTIL_HANDLE)WSASocketW (
                    family_, type_, protocol_, 0, 0, WSA_FLAG_OVERLAPPED)),
            #else // defined (TOOLCHAIN_OS_Windows)
                Stream ((THEKOGANS_UTIL_HANDLE)socket (family_, type_, protocol_)),
            #endif // defined (TOOLCHAIN_OS_Windows)
                family (family_),
                type (type_),
                protocol (protocol_) {
            if (!IsOpen ()) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
        }

        Socket::~Socket () {
            THEKOGANS_UTIL_TRY {
                Close ();
            }
            THEKOGANS_UTIL_CATCH_AND_LOG_SUBSYSTEM (THEKOGANS_STREAM)
        }

        util::TimeSpec Socket::GetReadTimeout () const {
        #if defined (TOOLCHAIN_OS_Windows)
            DWORD value = 0;
            socklen_t length = sizeof (value);
            if (getsockopt ((THEKOGANS_STREAM_SOCKET)handle, SOL_SOCKET,
                    SO_RCVTIMEO, (char *)&value, &length) == THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
            return util::TimeSpec::FromMilliseconds (value);
        #else // defined (TOOLCHAIN_OS_Windows)
            timeval timeVal;
            socklen_t length = sizeof (timeval);
            if (getsockopt ((THEKOGANS_STREAM_SOCKET)handle, SOL_SOCKET,
                    SO_RCVTIMEO, (char *)&timeVal, &length) == THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
            return util::TimeSpec (timeVal);
        #endif // defined (TOOLCHAIN_OS_Windows)
        }

        void Socket::SetReadTimeout (const util::TimeSpec &timeSpec) {
            if (timeSpec != util::TimeSpec::Infinite) {
            #if defined (TOOLCHAIN_OS_Windows)
                DWORD value = (DWORD)timeSpec.ToMilliseconds ();
                if (setsockopt ((THEKOGANS_STREAM_SOCKET)handle, SOL_SOCKET,
                        SO_RCVTIMEO, (char *)&value, sizeof (DWORD)) == THEKOGANS_STREAM_SOCKET_ERROR) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                }
            #else // defined (TOOLCHAIN_OS_Windows)
                timeval timeVal = timeSpec.Totimeval ();
                if (setsockopt ((THEKOGANS_STREAM_SOCKET)handle, SOL_SOCKET,
                        SO_RCVTIMEO, (char *)&timeVal, sizeof (timeval)) == THEKOGANS_STREAM_SOCKET_ERROR) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                }
            #endif // defined (TOOLCHAIN_OS_Windows)
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        util::TimeSpec Socket::GetWriteTimeout () const {
        #if defined (TOOLCHAIN_OS_Windows)
            DWORD value = 0;
            socklen_t length = sizeof (value);
            if (getsockopt ((THEKOGANS_STREAM_SOCKET)handle, SOL_SOCKET,
                    SO_SNDTIMEO, (char *)&value, &length) == THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
            return util::TimeSpec::FromMilliseconds (value);
        #else // defined (TOOLCHAIN_OS_Windows)
            timeval timeVal;
            socklen_t length = sizeof (timeval);
            if (getsockopt ((THEKOGANS_STREAM_SOCKET)handle, SOL_SOCKET,
                    SO_SNDTIMEO, (char *)&timeVal, &length) == THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
            return util::TimeSpec (timeVal);
        #endif // defined (TOOLCHAIN_OS_Windows)
        }

        void Socket::SetWriteTimeout (const util::TimeSpec &timeSpec) {
            if (timeSpec != util::TimeSpec::Infinite) {
            #if defined (TOOLCHAIN_OS_Windows)
                DWORD value = (DWORD)timeSpec.ToMilliseconds ();
                if (setsockopt ((THEKOGANS_STREAM_SOCKET)handle, SOL_SOCKET,
                        SO_SNDTIMEO, (char *)&value, sizeof (DWORD)) == THEKOGANS_STREAM_SOCKET_ERROR) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                }
            #else // defined (TOOLCHAIN_OS_Windows)
                timeval timeVal = timeSpec.Totimeval ();
                if (setsockopt ((THEKOGANS_STREAM_SOCKET)handle, SOL_SOCKET,
                        SO_SNDTIMEO, (char *)&timeVal, sizeof (timeval)) == THEKOGANS_STREAM_SOCKET_ERROR) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                }
            #endif // defined (TOOLCHAIN_OS_Windows)
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        std::string Socket::GetHostName () {
            char name[256];
            if (gethostname (name, 256) == THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
            return name;
        }

        std::size_t Socket::GetDataAvailable () const {
            u_long value = 0;
        #if defined (TOOLCHAIN_OS_Windows)
            if (ioctlsocket ((THEKOGANS_STREAM_SOCKET)handle, FIONREAD, &value) ==
                    THEKOGANS_STREAM_SOCKET_ERROR) {
        #else // defined (TOOLCHAIN_OS_Windows)
            if (ioctl ((THEKOGANS_STREAM_SOCKET)handle, FIONREAD, &value) ==
                    THEKOGANS_STREAM_SOCKET_ERROR) {
        #endif // defined (TOOLCHAIN_OS_Windows)
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
            return (std::size_t)value;
        }

        void Socket::Bind (const Address &address) {
            if (bind ((THEKOGANS_STREAM_SOCKET)handle, &address.address,
                    address.length) == THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
        }

        Address Socket::GetHostAddress () const {
            Address address;
            if (getsockname ((THEKOGANS_STREAM_SOCKET)handle,
                    &address.address, &address.length) == THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
            return address;
        }

        Address Socket::GetPeerAddress () const {
            Address address;
            if (getpeername ((THEKOGANS_STREAM_SOCKET)handle,
                    &address.address, &address.length) == THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
            return address;
        }

        void Socket::SetBlocking (bool blocking) {
            u_long arg = !blocking ? 1 : 0;
        #if defined (TOOLCHAIN_OS_Windows)
            if (ioctlsocket ((THEKOGANS_STREAM_SOCKET)handle, FIONBIO, &arg) ==
                    THEKOGANS_STREAM_SOCKET_ERROR) {
        #else // defined (TOOLCHAIN_OS_Windows)
            if (ioctl ((THEKOGANS_STREAM_SOCKET)handle, FIONBIO, &arg) ==
                    THEKOGANS_STREAM_SOCKET_ERROR) {
        #endif // defined (TOOLCHAIN_OS_Windows)
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
        }

        bool Socket::IsIPV6Only () const {
            int arg = 0;
            socklen_t length = sizeof (arg);
            if (getsockopt ((THEKOGANS_STREAM_SOCKET)handle, IPPROTO_IPV6,
                    IPV6_V6ONLY, (char *)&arg, &length) == THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
            return arg == 1;
        }

        void Socket::SetIPV6Only (bool ipv6Only) {
            u_long arg = ipv6Only ? 1 : 0;
            if (setsockopt ((THEKOGANS_STREAM_SOCKET)handle, IPPROTO_IPV6,
                    IPV6_V6ONLY, (char *)&arg, sizeof (arg)) == THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
        }

        bool Socket::IsReuseAddress () const {
            int arg = 0;
            socklen_t length = sizeof (arg);
            if (getsockopt ((THEKOGANS_STREAM_SOCKET)handle, SOL_SOCKET,
                    SO_REUSEADDR, (char *)&arg, &length) == THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
            return arg == 1;
        }

        void Socket::SetReuseAddress (bool reuseAddress) {
            u_long arg = reuseAddress ? 1 : 0;
            if (setsockopt ((THEKOGANS_STREAM_SOCKET)handle, SOL_SOCKET,
                    SO_REUSEADDR, (char *)&arg, sizeof (arg)) == THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
        }

    #if defined (SO_EXCLUSIVEADDRUSE)
        bool Socket::IsExclusiveAddressUse () const {
            int arg = 0;
            socklen_t length = sizeof (arg);
            if (getsockopt ((THEKOGANS_STREAM_SOCKET)handle, SOL_SOCKET,
                    SO_EXCLUSIVEADDRUSE, (char *)&arg, &length) == THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
            return arg == 1;
        }

        void Socket::SetExclusiveAddressUse (bool exclusiveAddressUse) {
            u_long arg = exclusiveAddressUse ? 1 : 0;
            if (setsockopt ((THEKOGANS_STREAM_SOCKET)handle, SOL_SOCKET,
                    SO_EXCLUSIVEADDRUSE, (char *)&arg, sizeof (arg)) == THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
        }
    #endif // defined (SO_EXCLUSIVEADDRUSE)

    #if defined (SO_REUSEPORT) || defined (SO_REUSE_UNICASTPORT)
        bool Socket::IsReusePort () const {
        #if defined (SO_REUSE_UNICASTPORT)
            DWORD arg = 0;
            socklen_t length = sizeof (arg);
            if (getsockopt ((THEKOGANS_STREAM_SOCKET)handle, SOL_SOCKET,
                    SO_REUSE_UNICASTPORT, (char *)&arg, &length) == THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
            return arg == 1;
        #else // defined (SO_REUSE_UNICASTPORT)
            int arg = 0;
            socklen_t length = sizeof (arg);
            if (getsockopt ((THEKOGANS_STREAM_SOCKET)handle, SOL_SOCKET,
                    SO_REUSEPORT, (char *)&arg, &length) == THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
            return arg == 1;
        #endif // defined (SO_REUSE_UNICASTPORT)
        }

        void Socket::SetReusePort (bool reusePort) {
        #if defined (SO_REUSE_UNICASTPORT)
            DWORD arg = reusePort ? 1 : 0;
            if (setsockopt ((THEKOGANS_STREAM_SOCKET)handle, SOL_SOCKET,
                    SO_REUSE_UNICASTPORT, (char *)&arg, sizeof (arg)) == THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
        #else // defined (SO_REUSE_UNICASTPORT)
            u_long arg = reusePort ? 1 : 0;
            if (setsockopt ((THEKOGANS_STREAM_SOCKET)handle, SOL_SOCKET,
                    SO_REUSEPORT, (char *)&arg, sizeof (arg)) == THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
        #endif // defined (SO_REUSE_UNICASTPORT)
        }
    #endif // defined (SO_REUSEPORT) || defined (SO_REUSE_UNICASTPORT)

        std::size_t Socket::GetSendBufferSize () const {
            util::ui32 size = 0;
            socklen_t length = sizeof (size);
            if (getsockopt ((THEKOGANS_STREAM_SOCKET)handle, SOL_SOCKET,
                    SO_SNDBUF, (char *)&size, &length) == THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
            return size;
        }

        void Socket::SetSendBufferSize (std::size_t size) {
            util::ui32 value = (util::ui32)size;
            if (setsockopt ((THEKOGANS_STREAM_SOCKET)handle, SOL_SOCKET,
                    SO_SNDBUF, (char *)&value, sizeof (value)) == THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
        }

        std::size_t Socket::GetReceiveBufferSize () const {
            util::ui32 size = 0;
            socklen_t length = sizeof (size);
            if (getsockopt ((THEKOGANS_STREAM_SOCKET)handle, SOL_SOCKET,
                    SO_RCVBUF, (char *)&size, &length) == THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
            return size;
        }

        void Socket::SetReceiveBufferSize (std::size_t size) {
            util::ui32 value = (util::ui32)size;
            if (setsockopt ((THEKOGANS_STREAM_SOCKET)handle, SOL_SOCKET,
                    SO_RCVBUF, (char *)&value, sizeof (value)) == THEKOGANS_STREAM_SOCKET_ERROR) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
        }

        THEKOGANS_UTIL_ERROR_CODE Socket::GetErrorCode () const {
            THEKOGANS_UTIL_ERROR_CODE errorCode = 0;
        #if defined (TOOLCHAIN_OS_Windows)
            socklen_t length = sizeof (errorCode);
            if (getsockopt ((THEKOGANS_STREAM_SOCKET)handle, SOL_SOCKET, SO_ERROR,
                    (char *)&errorCode, &length) == THEKOGANS_STREAM_SOCKET_ERROR) {
        #else // defined (TOOLCHAIN_OS_Windows)
            socklen_t length = sizeof (errorCode);
            if (getsockopt ((THEKOGANS_STREAM_SOCKET)handle, SOL_SOCKET, SO_ERROR,
                    &errorCode, &length) == THEKOGANS_STREAM_SOCKET_ERROR) {
        #endif // defined (TOOLCHAIN_OS_Windows)
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
            return errorCode;
        }

        void Socket::Close () {
            if (IsOpen ()) {
            #if defined (TOOLCHAIN_OS_Windows)
                if (closesocket ((THEKOGANS_STREAM_SOCKET)handle) == THEKOGANS_STREAM_SOCKET_ERROR) {
            #else // defined (TOOLCHAIN_OS_Windows)
                if (close ((THEKOGANS_STREAM_SOCKET)handle) == THEKOGANS_STREAM_SOCKET_ERROR) {
            #endif // defined (TOOLCHAIN_OS_Windows)
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_STREAM_SOCKET_ERROR_CODE);
                }
                handle = THEKOGANS_UTIL_INVALID_HANDLE_VALUE;
                family = -1;
                type = -1;
                protocol = -1;
            }
        }

    } // namespace stream
} // namespace thekogans
