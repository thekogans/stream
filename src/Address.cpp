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

#include <cassert>
#include "thekogans/util/Exception.h"
#include "thekogans/util/LoggerMgr.h"
#include "thekogans/util/XMLUtils.h"
#if defined (TOOLCHAIN_OS_Linux) || defined (TOOLCHAIN_OS_OSX)
    #include "thekogans/util/StringUtils.h"
#endif // defined (TOOLCHAIN_OS_Linux) || defined (TOOLCHAIN_OS_OSX)
#include "thekogans/stream/Socket.h"
#include "thekogans/stream/Address.h"

namespace thekogans {
    namespace stream {

        const Address Address::Empty;

        Address::Address (util::ui16 family) {
            if (family == AF_UNSPEC) {
                memset (this, 0, sizeof (sockaddr_storage));
                storage.ss_family = AF_UNSPEC;
            #if defined (TOOLCHAIN_OS_OSX)
                storage.ss_len =
            #endif // defined (TOOLCHAIN_OS_OSX)
                length = sizeof (sockaddr_storage);
            }
            else if (family == AF_INET) {
                memset (this, 0, sizeof (sockaddr_in));
                in.sin_family = AF_INET;
            #if defined (TOOLCHAIN_OS_OSX)
                in.sin_len =
            #endif // defined (TOOLCHAIN_OS_OSX)
                length = sizeof (sockaddr_in);
            }
            else if (family == AF_INET6) {
                memset (this, 0, sizeof (sockaddr_in6));
                in6.sin6_family = AF_INET6;
            #if defined (TOOLCHAIN_OS_OSX)
                in6.sin6_len =
            #endif // defined (TOOLCHAIN_OS_OSX)
                length = sizeof (sockaddr_in6);
            }
            else if (family == AF_LOCAL) {
                memset (this, 0, sizeof (sockaddr_un));
                un.sun_family = AF_LOCAL;
            #if defined (TOOLCHAIN_OS_OSX)
                un.sun_len =
            #endif // defined (TOOLCHAIN_OS_OSX)
                length = sizeof (sockaddr_un);
            }
        #if defined (TOOLCHAIN_OS_Linux)
            else if (family == AF_NETLINK) {
                memset (this, 0, sizeof (sockaddr_nl));
                nl.nl_family = AF_NETLINK;
                length = sizeof (sockaddr_nl);
            }
            else if (family == AF_PACKET) {
                memset (this, 0, sizeof (sockaddr_ll));
                ll.sll_family = AF_PACKET;
                length = sizeof (sockaddr_ll);
            }
        #elif defined (TOOLCHAIN_OS_OSX)
            else if (family == AF_LINK) {
                memset (this, 0, sizeof (sockaddr_dl));
                dl.sdl_family = AF_LINK;
                dl.sdl_len =
                length = sizeof (sockaddr_dl);
            }
        #endif // defined (TOOLCHAIN_OS_Linux)
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        Address::Address (
                util::ui16 port,
                const std::string &host,
                util::ui16 family) {
            memset (this, 0, sizeof (sockaddr_storage));
            storage.ss_family = AF_UNSPEC;
        #if defined (TOOLCHAIN_OS_OSX)
            storage.ss_len =
        #endif // defined (TOOLCHAIN_OS_OSX)
            length = sizeof (sockaddr_storage);
            addrinfo hints;
            memset (&hints, 0, sizeof (addrinfo));
            hints.ai_family = family;
            addrinfo *result = 0;
            if (getaddrinfo (host.c_str (), 0, &hints, &result) < 0) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
            if (result != 0) {
                // IPV4 or IPV6 address.
                if (family == AF_UNSPEC) {
                    for (const addrinfo *next = result; next != 0; next = next->ai_next) {
                        if (result->ai_addr != 0) {
                            if (result->ai_addr->sa_family == AF_INET) {
                                assert (result->ai_addrlen == sizeof (sockaddr_in));
                                memcpy (this, result->ai_addr, sizeof (sockaddr_in));
                                in.sin_port = htons (port);
                            #if defined (TOOLCHAIN_OS_OSX)
                                in.sin_len =
                            #endif // defined (TOOLCHAIN_OS_OSX)
                                length = sizeof (sockaddr_in);
                                break;
                            }
                            else if (result->ai_addr->sa_family == AF_INET6) {
                                assert (result->ai_addrlen == sizeof (sockaddr_in6));
                                memcpy (this, result->ai_addr, sizeof (sockaddr_in6));
                                in6.sin6_port = htons (port);
                            #if defined (TOOLCHAIN_OS_OSX)
                                in6.sin6_len =
                            #endif // defined (TOOLCHAIN_OS_OSX)
                                length = sizeof (sockaddr_in6);
                                break;
                            }
                        }
                    }
                }
                // IPV4 address.
                else if (family == AF_INET) {
                    for (const addrinfo *next = result; next != 0; next = next->ai_next) {
                        if (next->ai_addr != 0 && next->ai_addr->sa_family == AF_INET) {
                            assert (result->ai_addrlen == sizeof (sockaddr_in));
                            memcpy (this, next->ai_addr, sizeof (sockaddr_in));
                            in.sin_port = htons (port);
                        #if defined (TOOLCHAIN_OS_OSX)
                            in.sin_len =
                        #endif // defined (TOOLCHAIN_OS_OSX)
                            length = sizeof (sockaddr_in);
                            break;
                        }
                    }
                }
                // IPV6 address.
                else if (family == AF_INET6) {
                    for (const addrinfo *next = result; next != 0; next = next->ai_next) {
                        if (next->ai_addr != 0 && next->ai_addr->sa_family == AF_INET6) {
                            assert (result->ai_addrlen == sizeof (sockaddr_in6));
                            memcpy (this, next->ai_addr, sizeof (sockaddr_in6));
                            in6.sin6_port = htons (port);
                        #if defined (TOOLCHAIN_OS_OSX)
                            in6.sin6_len =
                        #endif // defined (TOOLCHAIN_OS_OSX)
                            length = sizeof (sockaddr_in6);
                            break;
                        }
                    }
                }
                freeaddrinfo (result);
                if (GetFamily () == AF_UNSPEC) {
                    if (family == AF_UNSPEC) {
                        THEKOGANS_UTIL_THROW_STRING_EXCEPTION ("%s",
                            "Unable to locate a suitable address for family AF_INET or AF_INET6");
                    }
                    else if (family == AF_INET) {
                        THEKOGANS_UTIL_THROW_STRING_EXCEPTION ("%s",
                            "Unable to locate a suitable address for family AF_INET");
                    }
                    else if (family == AF_INET6) {
                        THEKOGANS_UTIL_THROW_STRING_EXCEPTION ("%s",
                            "Unable to locate a suitable address for family AF_INET6");
                    }
                    else {
                        THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                            THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
                    }
                }
            }
            else {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "Unable to resolve address: %s:%u for family: %s",
                    host.c_str (), port, FamilyToString (family).c_str ());
            }
        }

        Address::Address (
                util::ui16 port,
                const in_addr &addr) {
            memset (this, 0, sizeof (sockaddr_in));
            in.sin_family = AF_INET;
            in.sin_port = htons (port);
            in.sin_addr = addr;
        #if defined (TOOLCHAIN_OS_OSX)
            in.sin_len =
        #endif // defined (TOOLCHAIN_OS_OSX)
            length = sizeof (sockaddr_in);
        }

    #if !defined (TOOLCHAIN_OS_Windows)
        Address::Address (
                util::ui16 port,
                const std::string &network,
                const in_addr &addr) {
            memset (this, 0, sizeof (sockaddr_in));
            // FIXME: not sure if this is thread safe.
            const netent *ne = getnetbyname (network.c_str ());
            if (ne == 0) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_STREAM_SOCKET_ERROR_CODE);
            }
            in.sin_family = AF_INET;
            in.sin_port = htons (port);
            in.sin_addr = inet_makeaddr (ne->n_net, addr.s_addr);
        #if defined (TOOLCHAIN_OS_OSX)
            in.sin_len =
        #endif // defined (TOOLCHAIN_OS_OSX)
            length = sizeof (sockaddr_in);
        }
    #endif // !defined (TOOLCHAIN_OS_Windows)

        Address::Address (
                util::ui16 port,
                const in6_addr &addr) {
            memset (this, 0, sizeof (sockaddr_in6));
            in6.sin6_family = AF_INET6;
            in6.sin6_port = htons (port);
            in6.sin6_addr = addr;
        #if defined (TOOLCHAIN_OS_OSX)
            in6.sin6_len =
        #endif // defined (TOOLCHAIN_OS_OSX)
            length = sizeof (sockaddr_in6);
        }

        Address::Address (const std::string &path) {
            if (path.size () < sizeof (un.sun_path)) {
                memset (this, 0, sizeof (sockaddr_un));
                un.sun_family = AF_LOCAL;
            #if defined (TOOLCHAIN_OS_Windows)
                strncpy_s (un.sun_path, sizeof (un.sun_path), path.c_str (), sizeof (un.sun_path));
            #else // defined (TOOLCHAIN_OS_Windows)
                strncpy (un.sun_path, path.c_str (), sizeof (un.sun_path));
            #endif // defined (TOOLCHAIN_OS_Windows)
            #if defined (TOOLCHAIN_OS_OSX)
                un.sun_len =
            #endif // defined (TOOLCHAIN_OS_OSX)
                length = sizeof (sockaddr_un);
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        Address Address::Any (
                util::ui16 port,
                util::ui16 family) {
            if (family == AF_INET) {
                in_addr in;
                in.s_addr = htonl (INADDR_ANY);
                return Address (port, in);
            }
            else if (family == AF_INET6) {
                in6_addr in6;
                in6 = in6addr_any;
                return Address (port, in6);
            }
            return Empty;
        }

        Address Address::Loopback (
                util::ui16 port,
                util::ui16 family) {
            if (family == AF_INET) {
                in_addr in;
                in.s_addr = htonl (INADDR_LOOPBACK);
                return Address (port, in);
            }
            else if (family == AF_INET6) {
                in6_addr in6;
                in6 = in6addr_loopback;
                return Address (port, in6);
            }
            return Empty;
        }

        void Address::SetFamily (util::ui16 family) {
            if (family == AF_UNSPEC) {
                memset (this, 0, sizeof (sockaddr_storage));
                storage.ss_family = AF_UNSPEC;
            #if defined (TOOLCHAIN_OS_OSX)
                storage.ss_len =
            #endif // defined (TOOLCHAIN_OS_OSX)
                length = sizeof (sockaddr_storage);
            }
            else if (family == AF_INET) {
                memset (this, 0, sizeof (sockaddr_in));
                in.sin_family = AF_INET;
            #if defined (TOOLCHAIN_OS_OSX)
                in.sin_len =
            #endif // defined (TOOLCHAIN_OS_OSX)
                length = sizeof (sockaddr_in);
            }
            else if (family == AF_INET6) {
                memset (this, 0, sizeof (sockaddr_in6));
                in6.sin6_family = AF_INET6;
            #if defined (TOOLCHAIN_OS_OSX)
                in6.sin6_len =
            #endif // defined (TOOLCHAIN_OS_OSX)
                length = sizeof (sockaddr_in6);
            }
            else if (family == AF_LOCAL) {
                memset (this, 0, sizeof (sockaddr_un));
                un.sun_family = AF_LOCAL;
            #if defined (TOOLCHAIN_OS_OSX)
                un.sun_len =
            #endif // defined (TOOLCHAIN_OS_OSX)
                length = sizeof (sockaddr_un);
            }
        #if defined (TOOLCHAIN_OS_Linux)
            else if (family == AF_LOCAL) {
                memset (this, 0, sizeof (sockaddr_nl));
                nl.nl_family = AF_NETLINK;
                length = sizeof (sockaddr_nl);
            }
            else if (family == AF_PACKET) {
                memset (this, 0, sizeof (sockaddr_ll));
                ll.sll_family = AF_PACKET;
                length = sizeof (sockaddr_ll);
            }
        #elif defined (TOOLCHAIN_OS_OSX)
            else if (family == AF_LINK) {
                memset (this, 0, sizeof (sockaddr_dl));
                dl.sdl_family = AF_LINK;
                dl.sdl_len =
                length = sizeof (sockaddr_dl);
            }
        #endif // defined (TOOLCHAIN_OS_Linux)
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        std::string Address::FamilyToString (util::ui16 family) {
            return
                family == AF_INET ? VALUE_FAMILY_INET :
                family == AF_INET6 ? VALUE_FAMILY_INET6 :
                family == AF_LOCAL ? VALUE_FAMILY_LOCAL :
            #if defined (TOOLCHAIN_OS_Linux)
                family == AF_NETLINK ? VALUE_FAMILY_NETLINK :
                family == AF_PACKET ? VALUE_FAMILY_PACKET :
            #elif defined (TOOLCHAIN_OS_OSX)
                family == AF_LINK ? VALUE_FAMILY_LINK :
            #endif // defined (TOOLCHAIN_OS_Linux)
                VALUE_FAMILY_UNSPEC;
        }

        util::ui16 Address::StringToFamily (const std::string &family) {
            return
                family == VALUE_FAMILY_INET ? AF_INET :
                family == VALUE_FAMILY_INET6 ? AF_INET6 :
                family == VALUE_FAMILY_LOCAL ? AF_LOCAL :
            #if defined (TOOLCHAIN_OS_Linux)
                family == VALUE_FAMILY_NETLINK ? AF_NETLINK :
                family == VALUE_FAMILY_PACKET ? AF_PACKET :
            #elif defined (TOOLCHAIN_OS_OSX)
                family == VALUE_FAMILY_LINK ? AF_LINK :
            #endif // defined (TOOLCHAIN_OS_Linux)
                AF_UNSPEC;
        }

        util::ui16 Address::GetPort () const {
            util::ui16 family = GetFamily ();
            return
                family == AF_INET ? ntohs (in.sin_port) :
                family == AF_INET6 ? ntohs (in6.sin6_port) : -1;
        }

        void Address::SetPort (util::ui16 port) {
            util::ui16 family = GetFamily ();
            if (family == AF_INET) {
                in.sin_port = htons (port);
            }
            else if (family == AF_INET6) {
                in6.sin6_port = htons (port);
            }
            else {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "Invalid family (%s) for port.",
                    FamilyToString (family).c_str ());
            }
        }

        in_addr Address::GetAddr () const {
            static const in_addr empty = {0};
            return GetFamily () == AF_INET ? in.sin_addr : empty;
        }

        void Address::SetAddr (const in_addr &addr) {
            if (GetFamily () == AF_INET) {
                in.sin_addr = addr;
            }
            else {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "Invalid family (%s) for address.",
                    FamilyToString (GetFamily ()).c_str ());
            }
        }

        in6_addr Address::GetAddr6 () const {
            static const in6_addr empty = {{{0}}};
            return GetFamily () == AF_INET6 ? in6.sin6_addr : empty;
        }

        void Address::SetAddr (const in6_addr &addr) {
            if (GetFamily () == AF_INET6) {
                in6.sin6_addr = addr;
            }
            else {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "Invalid family (%s) for address.",
                    FamilyToString (GetFamily ()).c_str ());
            }
        }

        std::string Address::AddrToString () const {
            if (GetFamily () == AF_INET) {
                char buffer[INET_ADDRSTRLEN];
                inet_ntop (GetFamily (), (void *)&in.sin_addr.s_addr,
                    buffer, INET_ADDRSTRLEN);
                return buffer;
            }
            else if (GetFamily () == AF_INET6) {
                char buffer[INET6_ADDRSTRLEN];
                inet_ntop (GetFamily (), (void *)&in6.sin6_addr,
                    buffer, INET6_ADDRSTRLEN);
                return buffer;
            }
            else if (GetFamily () == AF_LOCAL) {
                return un.sun_path;
            }
            return std::string ();
        }

        std::string Address::GetPath () const {
            return GetFamily () == AF_LOCAL ? un.sun_path : std::string ();
        }

        void Address::SetPath (const std::string &path) {
            if (path.size () < sizeof (un.sun_path)) {
                if (GetFamily () == AF_LOCAL) {
                #if defined (TOOLCHAIN_OS_Windows)
                    strncpy_s (un.sun_path, sizeof (un.sun_path), path.c_str (), sizeof (un.sun_path));
                #else // defined (TOOLCHAIN_OS_Windows)
                    strncpy (un.sun_path, path.c_str (), sizeof (un.sun_path));
                #endif // defined (TOOLCHAIN_OS_Windows)
                }
                else {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Invalid family (%s) for path.",
                        FamilyToString (GetFamily ()).c_str ());
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

    #if defined (TOOLCHAIN_OS_Linux)
        util::ui32 Address::GetGroups () const {
            return GetFamily () == AF_NETLINK ? nl.nl_groups : 0;
        }

        void Address::SetGroups (util::ui32 groups) {
            if (GetFamily () == AF_NETLINK) {
                nl.nl_groups = groups;
            }
            else {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "Invalid family (%s) for groups.",
                    FamilyToString (GetFamily ()).c_str ());
            }
        }

        util::ui16 Address::GetProtocol () const {
            return GetFamily () == AF_PACKET ? ntohs (ll.sll_protocol) : 0;
        }

        void Address::SetProtocol (util::ui16 protocol) {
            if (GetFamily () == AF_PACKET) {
                ll.sll_protocol = htons (protocol);
            }
            else {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "Invalid family (%s) for protocol.",
                    FamilyToString (GetFamily ()).c_str ());
            }
        }

        util::i32 Address::GetAdapterIndex () const {
            return GetFamily () == AF_PACKET ? ll.sll_ifindex : 0;
        }

        void Address::SetAdapterIndex (util::i32 index) {
            if (GetFamily () == AF_PACKET) {
                ll.sll_ifindex = index;
            }
            else {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "Invalid family (%s) for index.",
                    FamilyToString (GetFamily ()).c_str ());
            }
        }

        std::vector<util::ui8> Address::GetAddrPacket () const {
            return GetFamily () == AF_PACKET ?
                std::vector<util::ui8> (ll.sll_addr, ll.sll_addr + ll.sll_halen) : std::vector<util::ui8> ();
        }

        void Address::SetAddr (const std::vector<util::ui8> &addr) {
            if (addr.size () > 0 && addr.size () <= 8) {
                if (GetFamily () == AF_PACKET) {
                    ll.sll_halen = (util::ui8)addr.size ();
                    memcpy (ll.sll_addr, &addr[0], addr.size ());
                }
                else {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Invalid family (%s) for addr.",
                        FamilyToString (GetFamily ()).c_str ());
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }
    #elif defined (TOOLCHAIN_OS_OSX)
        util::i32 Address::GetAdapterIndex () const {
            return GetFamily () == AF_LINK ? dl.sdl_index : 0;
        }

        void Address::SetAdapterIndex (util::i32 index) {
            if (GetFamily () == AF_LINK) {
                dl.sdl_index = index;
            }
            else {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "Invalid family (%s) for index.",
                    FamilyToString (GetFamily ()).c_str ());
            }
        }

        std::string Address::GetAdapterName () const {
            return GetFamily () == AF_LINK ?
                std::string (dl.sdl_data, dl.sdl_data + dl.sdl_nlen) : 0;
        }

        void Address::SetAdapterName (const std::string &name) {
            if (GetFamily () == AF_LINK) {
                dl.sdl_nlen = name.size ();
                if (dl.sdl_nlen > 0) {
                    memcpy (dl.sdl_data, &name[0], name.size ());
                }
            }
            else {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "Invalid family (%s) for index.",
                    FamilyToString (GetFamily ()).c_str ());
            }
        }

        std::vector<util::ui8> Address::GetAddrLink () const {
            return GetFamily () == AF_LINK ?
                std::vector<util::ui8> (
                    dl.sdl_data + dl.sdl_nlen,
                    dl.sdl_data + dl.sdl_nlen + dl.sdl_alen) :
                std::vector<util::ui8> ();
        }

        void Address::SetAddr (const std::vector<util::ui8> &addr) {
            if (addr.size () > 0 && addr.size () <= 8) {
                if (GetFamily () == AF_LINK) {
                    dl.sdl_alen = (util::ui8)addr.size ();
                    memcpy (dl.sdl_data + dl.sdl_nlen, &addr[0], addr.size ());
                }
                else {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Invalid family (%s) for addr.",
                        FamilyToString (GetFamily ()).c_str ());
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }
    #endif // defined (TOOLCHAIN_OS_Linux)

        const char * const Address::TAG_ADDRESS = "Address";
        const char * const Address::ATTR_FAMILY = "Family";
        const char * const Address::VALUE_FAMILY_UNSPEC = "unspec";
        const char * const Address::VALUE_FAMILY_INET = "inet";
        const char * const Address::VALUE_FAMILY_INET6 = "inet6";
        const char * const Address::VALUE_FAMILY_LOCAL = "local";
    #if defined (TOOLCHAIN_OS_Linux)
        const char * const Address::VALUE_FAMILY_NETLINK = "netlink";
        const char * const Address::VALUE_FAMILY_PACKET = "packet";
    #elif defined (TOOLCHAIN_OS_OSX)
        const char * const Address::VALUE_FAMILY_LINK = "link";
    #endif // defined (TOOLCHAIN_OS_Linux)
        const char * const Address::ATTR_PORT = "Port";
        const char * const Address::ATTR_ADDR = "Addr";
        const char * const Address::VALUE_ADDR_ANY = "any";
        const char * const Address::VALUE_ADDR_LOOPBACK = "loopback";
        const char * const Address::ATTR_PATH = "Path";
    #if defined (TOOLCHAIN_OS_Linux)
        const char * const Address::ATTR_GROUPS = "Groups";
        const char * const Address::ATTR_PROTOCOL = "Protocol";
        const char * const Address::ATTR_ADAPTER_INDEX = "AdapterIndex";
    #elif defined (TOOLCHAIN_OS_OSX)
        const char * const Address::ATTR_ADAPTER_INDEX = "AdapterIndex";
        const char * const Address::ATTR_ADAPTER_NAME = "AdapterName";
    #endif // defined (TOOLCHAIN_OS_Linux)

        void Address::FromString (const std::string &addressString) {
            pugi::xml_document document;
            pugi::xml_parse_result result =
                document.load_buffer (addressString.c_str (), addressString.size ());
            if (result) {
                Parse (document.document_element ());
            }
            else {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "Unable to parse:\n%s\n%s",
                    addressString.c_str (),
                    result.description ());
            }
        }

        void Address::Parse (const pugi::xml_node &node) {
            std::string family = node.attribute (ATTR_FAMILY).value ();
            if (family == VALUE_FAMILY_UNSPEC) {
                SetFamily (AF_UNSPEC);
            }
            else if (family == VALUE_FAMILY_INET) {
                SetFamily (AF_INET);
                std::string port = node.attribute (ATTR_PORT).value ();
                SetPort (util::stringToui16 (port.c_str ()));
                std::string addr = util::Decodestring (
                    node.attribute (ATTR_ADDR).value ());
                if (addr == VALUE_ADDR_ANY) {
                    in.sin_addr.s_addr = htonl (INADDR_ANY);
                }
                else if (addr == VALUE_ADDR_LOOPBACK) {
                    in.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
                }
                else {
                    inet_pton (AF_INET, addr.c_str (), &in.sin_addr.s_addr);
                }
            }
            else if (family == VALUE_FAMILY_INET6) {
                SetFamily (AF_INET6);
                std::string port = node.attribute (ATTR_PORT).value ();
                SetPort (util::stringToui16 (port.c_str ()));
                std::string addr = util::Decodestring (
                    node.attribute (ATTR_ADDR).value ());
                if (addr == VALUE_ADDR_ANY) {
                    in6.sin6_addr = in6addr_any;
                }
                else if (addr == VALUE_ADDR_LOOPBACK) {
                    in6.sin6_addr = in6addr_loopback;
                }
                else {
                    inet_pton (AF_INET6, addr.c_str (), &in6.sin6_addr);
                }
            }
            else if (family == VALUE_FAMILY_LOCAL) {
                SetFamily (AF_LOCAL);
                SetPath (util::Decodestring (node.attribute (ATTR_PATH).value ()));
            }
        #if defined (TOOLCHAIN_OS_Linux)
            else if (family == VALUE_FAMILY_NETLINK) {
                SetFamily (AF_NETLINK);
                std::string groups = node.attribute (ATTR_GROUPS).value ();
                SetPort (util::stringToui32 (groups.c_str ()));
            }
            else if (family == VALUE_FAMILY_PACKET) {
                SetFamily (AF_PACKET);
                std::string protocol = node.attribute (ATTR_PROTOCOL).value ();
                std::string adapterIndex = node.attribute (ATTR_ADAPTER_INDEX).value ();
                std::string addr = node.attribute (ATTR_ADDR).value ();
                SetProtocol (util::stringToui16 (protocol.c_str ()));
                SetAdapterIndex (util::stringToi32 (adapterIndex.c_str ()));
                SetAddr (util::HexDecodestring (addr.c_str ()));
            }
        #elif defined (TOOLCHAIN_OS_OSX)
            else if (family == VALUE_FAMILY_LINK) {
                SetFamily (AF_LINK);
                std::string adapterIndex = node.attribute (ATTR_ADAPTER_INDEX).value ();
                std::string adapterName = node.attribute (ATTR_ADAPTER_NAME).value ();
                std::string addr = node.attribute (ATTR_ADDR).value ();
                SetAdapterIndex (util::stringToi32 (adapterIndex.c_str ()));
                SetAdapterName (adapterName);
                SetAddr (util::HexDecodestring (addr.c_str ()));
            }
        #endif // defined (TOOLCHAIN_OS_Linux)
            else {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "Invalid family (%s).", family.c_str ());
            }
        }

        std::string Address::ToString (
                std::size_t indentationLevel,
                const char *tagName) const {
            if (tagName != 0) {
                util::Attributes attributes;
                util::ui16 family = GetFamily ();
                if (family == AF_INET) {
                    attributes.push_back (util::Attribute (ATTR_FAMILY, VALUE_FAMILY_INET));
                    attributes.push_back (util::Attribute (ATTR_PORT, util::ui32Tostring (GetPort ())));
                    attributes.push_back (
                        util::Attribute (ATTR_ADDR,
                            ntohl (in.sin_addr.s_addr) == INADDR_ANY ?
                                VALUE_ADDR_ANY :
                                ntohl (in.sin_addr.s_addr) == INADDR_LOOPBACK ?
                                    VALUE_ADDR_LOOPBACK :
                                    util::Encodestring (AddrToString ())));
                }
                else if (family == AF_INET6) {
                    attributes.push_back (util::Attribute (ATTR_FAMILY, VALUE_FAMILY_INET6));
                    attributes.push_back (util::Attribute (ATTR_PORT, util::ui32Tostring (GetPort ())));
                    attributes.push_back (
                        util::Attribute (ATTR_ADDR,
                            memcmp (&in6.sin6_addr, &in6addr_any, sizeof (in6addr_any)) == 0 ?
                                VALUE_ADDR_ANY :
                                memcmp (&in6.sin6_addr, &in6addr_loopback, sizeof (in6addr_loopback)) == 0 ?
                                    VALUE_ADDR_LOOPBACK :
                                    util::Encodestring (AddrToString ())));
                }
                else if (family == AF_LOCAL) {
                    attributes.push_back (util::Attribute (ATTR_FAMILY, VALUE_FAMILY_LOCAL));
                    attributes.push_back (util::Attribute (ATTR_PATH, util::Encodestring (GetPath ())));
                }
            #if defined (TOOLCHAIN_OS_Linux)
                else if (family == AF_NETLINK) {
                    attributes.push_back (util::Attribute (ATTR_FAMILY, VALUE_FAMILY_NETLINK));
                    attributes.push_back (util::Attribute (ATTR_GROUPS, util::ui32Tostring (GetGroups ())));
                }
                else if (family == AF_PACKET) {
                    attributes.push_back (util::Attribute (ATTR_FAMILY, VALUE_FAMILY_PACKET));
                    attributes.push_back (util::Attribute (ATTR_PROTOCOL, util::ui32Tostring (GetProtocol ())));
                    attributes.push_back (util::Attribute (ATTR_ADAPTER_INDEX, util::i32Tostring (GetAdapterIndex ())));
                    attributes.push_back (util::Attribute (ATTR_ADDR, util::HexEncodeBuffer (ll.sll_addr, ll.sll_halen)));
                }
            #elif defined (TOOLCHAIN_OS_OSX)
                else if (family == AF_LINK) {
                    attributes.push_back (util::Attribute (ATTR_FAMILY, VALUE_FAMILY_LINK));
                    attributes.push_back (util::Attribute (ATTR_ADAPTER_INDEX, util::i32Tostring (GetAdapterIndex ())));
                    attributes.push_back (util::Attribute (ATTR_ADAPTER_NAME, GetAdapterName ()));
                    attributes.push_back (util::Attribute (ATTR_ADDR, util::HexEncodeBuffer (dl.sdl_data + dl.sdl_nlen, dl.sdl_alen)));
                }
            #endif // defined (TOOLCHAIN_OS_Linux)
                else {
                    attributes.push_back (util::Attribute (ATTR_FAMILY, VALUE_FAMILY_UNSPEC));
                }
                return util::OpenTag (indentationLevel, tagName, attributes, true, true);
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        _LIB_THEKOGANS_STREAM_DECL bool _LIB_THEKOGANS_STREAM_API operator == (
                const Address &address1,
                const Address &address2) {
            return address1.length == address2.length &&
                memcmp (&address1, &address2, address1.length) == 0;
        }

        _LIB_THEKOGANS_STREAM_DECL bool _LIB_THEKOGANS_STREAM_API operator != (
                const Address &address1,
                const Address &address2) {
            return address1.length != address2.length ||
                memcmp (&address1, &address2, address1.length) != 0;
        }

    } // namespace stream
} // namespace thekogans
