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

#if !defined (__thekogans_stream_Address_h)
#define __thekogans_stream_Address_h

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
    #include <iphlpapi.h>
    #include <ws2tcpip.h>
    #include <mswsock.h>
    #if !defined (UNIX_PATH_MAX)
        #define UNIX_PATH_MAX 108
    #endif // !defined (UNIX_PATH_MAX)
    #if !defined (AF_LOCAL)
        #define AF_LOCAL 1
    #endif // !defined (AF_LOCAL)
#else // defined (TOOLCHAIN_OS_Windows)
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <sys/un.h>
    #include <arpa/inet.h>
    #include <netdb.h>
    #if defined (TOOLCHAIN_OS_Linux)
        #include <linux/netlink.h>
        #include <linux/if_packet.h>
        #include <net/ethernet.h>
    #elif defined (TOOLCHAIN_OS_OSX)
        #include <net/if_dl.h>
    #endif // defined (TOOLCHAIN_OS_Linux)
    #include <vector>
#endif // defined (TOOLCHAIN_OS_Windows)
#include <string>
#if defined (THEKOGANS_STREAM_HAVE_PUGIXML)
    #include <pugixml.hpp>
#endif // defined (THEKOGANS_STREAM_HAVE_PUGIXML)
#include "thekogans/util/Types.h"
#include "thekogans/stream/Config.h"

namespace thekogans {
    namespace stream {

        /// \struct Address Address.h thekogans/stream/Address.h
        ///
        /// \brief
        /// Address puts a mostly uniform api on top of sockaddr*.
        /// It's designed to work with _in, _in6 and _un address
        /// families on all platforms. On Linux, support for _nl
        /// and _ll address types is provided. On OS X support for
        /// _dl address type is provided.
        /// NOTE: On Windows sockaddr_un is used as a named pipe
        /// address (See \see{ClientNamedPipe} and \see{ServerNamedPipe}).
        /// This puts a uniform Address on all streams.

        struct _LIB_THEKOGANS_STREAM_DECL Address {
        #if defined (TOOLCHAIN_OS_Windows)
            /// \struct Address::sockaddr_un Address.h thekogans/stream/Address.h
            ///
            /// \brief
            /// Windows does not support sockaddr_un. So we define
            /// it here, and use it to represent named pipe addresses.
            struct sockaddr_un {
                /// \brief
                /// AF_LOCAL
                util::ui16 sun_family;
                /// \brief
                /// Properly formated named pipe address.
                char sun_path[UNIX_PATH_MAX];
            };
        #endif // defined (TOOLCHAIN_OS_Windows)
            union {
                /// \brief
                /// Catchall.
                sockaddr address;
                /// \brief
                /// AF_INET address.
                sockaddr_in in;
                /// \brief
                /// AF_INET6 address.
                sockaddr_in6 in6;
                /// \brief
                /// AF_LOCAL address.
                sockaddr_un un;
            #if defined (TOOLCHAIN_OS_Linux)
                /// \brief
                /// AF_NETLINK address.
                sockaddr_nl nl;
                /// \brief
                /// AF_PACKET address.
                sockaddr_ll ll;
            #elif defined (TOOLCHAIN_OS_OSX)
                /// \brief
                /// AF_LINK address.
                sockaddr_dl dl;
            #endif // defined (TOOLCHAIN_OS_Linux)
                /// \brief
                /// Used to get info from sockets.
                sockaddr_storage storage;
            };
            /// \brief
            /// Union specific length.
            socklen_t length;

            /// \brief
            /// An empty address. Empty is initialized to AF_UNSPEC:0.0.0.0:0.
            /// The most important part of that is AF_UNSPEC (since 0.0.0.0:0
            /// is actually a valid address).
            static const Address Empty;

            /// \brief
            /// ctor.
            /// Create an empty adderss for a given family.
            /// Works with sockddr_in[6] and sockddr_un.
            /// \param[in] family (AF_INET | AF_INET6 | AF_LOCAL | AF_UNSPEC)
            Address (util::ui16 family = AF_UNSPEC);
            /// \brief
            /// ctor.
            /// This is the main workhorse ctor. It creates
            /// either an IPV4 or IPV6 address given a port
            /// and a host name.
            /// \param[in] port Address port.
            /// \param[in] host Host name.
            /// \param[in] family AF_INET or AF_INET6.
            /// If you leave family as AF_UNSPEC, it will chose
            /// the first available IPV4 or IPV6 address and
            /// initialize appropriately.
            Address (
                util::ui16 port,
                const std::string &host,
                util::ui16 family = AF_UNSPEC);
            /// \brief
            /// ctor.
            /// Create an address from a port and a given
            /// IPV4 host address.
            /// Works with sockddr_in.
            /// \param[in] port Address port.
            /// \param[in] addr IPV4 host address.
            Address (
                util::ui16 port,
                const in_addr &addr);
        #if !defined (TOOLCHAIN_OS_Windows)
            /// \brief
            /// ctor.
            /// Create an address given a network number, and
            /// a local host address. This is a legacy ctor
            /// which assumes is dealing with classful network
            /// address.
            /// \param[in] port Address port.
            /// \param[in] network Classful network number.
            /// \param[in] addr Local host address.
            Address (
                util::ui16 port,
                const std::string &network,
                const in_addr &addr);
        #endif // !defined (TOOLCHAIN_OS_Windows)
            /// \brief
            /// ctor.
            /// Create an address from a port and a given
            /// IPV6 host address.
            /// Works with sockddr_in6.
            /// \param[in] port Address port.
            /// \param[in] addr IPV6 host address.
            Address (
                util::ui16 port,
                const in6_addr &addr);
            /// \brief
            /// ctor.
            /// Create an sockddr_un address from
            /// a given UNIX domain path or Windows named pipe ("\\.\pipe\pipename").
            /// \param[in] path UNIX domain path or Windows named pipe.
            explicit Address (const std::string &path);

            /// \brief
            /// Given a family and port, create an address that
            /// can be used to listen on all available interfaces.
            /// \param[in] port Address port.
            /// \param[in] family Address family.
            /// \return An initialized address for listenning
            /// on all interfaces.
            static Address Any (
                util::ui16 port,
                util::ui16 family = AF_INET);
            /// \brief
            /// Given a family and port, create an address that
            /// can be used to listen on the loop back adapter.
            /// \param[in] port Address port.
            /// \param[in] family Address family.
            /// \return An initialized address for listenning
            /// on the loop back adapter.
            static Address Loopback (
                util::ui16 port,
                util::ui16 family = AF_INET);

            /// \brief
            /// Return address family.
            /// \return Address family.
            inline util::ui16 GetFamily () const {
                return address.sa_family;
            }
            /// \brief
            /// Set address family.
            /// \param[in] family Address family.
            /// NOTE: This function will first clear the address
            /// to '0', and will than initialize the family and
            /// length appropriately.
            void SetFamily (util::ui16 family);
            /// \brief
            /// Convert a given family to a string representation.
            /// \param[in] family Family to convert.
            /// \return String representation of the given family.
            static std::string FamilyToString (util::ui16 family);
            /// \brief
            /// Convert a given family string representation to family.
            /// \param[in] family String representation of family to convert.
            /// \return Family of the given string representation.
            static util::ui16 StringToFamily (const std::string &family);

            /// \brief
            /// Return address port.
            /// \return Address port.
            util::ui16 GetPort () const;
            /// \brief
            /// Set address port.
            /// \param[in] port Address port.
            void SetPort (util::ui16 port);

            /// \brief
            /// Return the IPV4 address.
            /// \return IPV4 address.
            /// NOTE: Adderss family must be AF_INET.
            in_addr GetAddr () const;
            /// \brief
            /// Set the IPV4 address.
            /// \param[in] addr IPV4 address.
            /// NOTE: Adderss family must be AF_INET.
            void SetAddr (const in_addr &addr);

            /// \brief
            /// Return the IPV6 address.
            /// \return IPV6 address.
            /// NOTE: Adderss family must be AF_INET6.
            in6_addr GetAddr6 () const;
            /// \brief
            /// Set the IPV6 address.
            /// \param[in] addr IPV6 address.
            /// NOTE: Adderss family must be AF_INET6.
            void SetAddr (const in6_addr &addr);

            /// \brief
            /// Return the string representation of the address.
            /// Address family can be AF_INET, AF_INET6 or AF_LOCAL.
            /// \return String representation of the address.
            std::string AddrToString () const;

            /// \brief
            /// Return the UNIX domain path of the AF_LOCAL address.
            /// \return UNIX domain path.
            std::string GetPath () const;
            /// \brief
            /// Set the UNIX domain path of the AF_LOCAL address.
            /// \param[in] path UNIX domain path.
            void SetPath (const std::string &path);

        #if defined (TOOLCHAIN_OS_Linux)
            /// \brief
            /// Return nl.nl_groups if AF_NETLINK, 0 otherwise.
            /// \return nl.nl_groups if AF_NETLINK, 0 otherwise.
            util::ui32 GetGroups () const;
            /// \brief
            /// Set nl.nl_groups.
            /// \param[in] groups Netlink multicast groups.
            void SetGroups (util::ui32 groups);

            /// \brief
            /// Return ll.sll_protocol if AF_PACKET, 0 otherwise.
            /// \return ll.sll_protocol if AF_PACKET, 0 otherwise.
            util::ui16 GetProtocol () const;
            /// \brief
            /// Set ll.sll_protocol.
            /// \param[in] protocol Packet protocol.
            void SetProtocol (util::ui16 protocol);

            /// \brief
            /// Return ll.sll_ifindex if AF_PACKET, 0 otherwise.
            /// \return ll.sll_ifindex if AF_PACKET, 0 otherwise.
            util::i32 GetAdapterIndex () const;
            /// \brief
            /// Set ll.sll_ifindex.
            /// \param[in] index Packet adapter index.
            void SetAdapterIndex (util::i32 index);

            /// \brief
            /// Return ll.sll_addr if AF_PACKET, 0 otherwise.
            /// \return ll.sll_addr if AF_PACKET, 0 otherwise.
            std::vector<util::ui8> GetAddrPacket () const;
            /// \brief
            /// Set ll.sll_addr.
            /// \param[in] addr Packet adapter address.
            void SetAddr (const std::vector<util::ui8> &addr);
        #elif defined (TOOLCHAIN_OS_OSX)
            /// \brief
            /// Return dl.sdl_index if AF_LINK, 0 otherwise.
            /// \return dl.sdl_index if AF_LINK, 0 otherwise.
            util::i32 GetAdapterIndex () const;
            /// \brief
            /// Set dl.sdl_index.
            /// \param[in] index Link adapter index.
            void SetAdapterIndex (util::i32 index);

            /// \brief
            /// Return dl.sdl_data if AF_LINK, std::string () otherwise.
            /// \return dl.sdl_data if AF_LINK, std::string () otherwise.
            std::string GetAdapterName () const;
            /// \brief
            /// Set dl.sdl_data.
            /// \param[in] name Link adapter name.
            void SetAdapterName (const std::string &name);

            /// \brief
            /// Return LLADDR (&dl) if AF_LINK, std::vector<util::ui8> () otherwise.
            /// \return LLADDR (&dl) if AF_LINK, std::vector<util::ui8> () otherwise.
            std::vector<util::ui8> GetAddrLink () const;
            /// \brief
            /// Set LLADDR (&dl).
            /// \param[in] addr Link adapter address.
            void SetAddr (const std::vector<util::ui8> &addr);
        #endif // defined (TOOLCHAIN_OS_Linux)

            /// \brief
            /// "Address"
            static const char * const TAG_ADDRESS;
            /// \brief
            /// "Family"
            static const char * const ATTR_FAMILY;
            /// \brief
            /// "unspec"
            static const char * const VALUE_FAMILY_UNSPEC;
            /// \brief
            /// "inet"
            static const char * const VALUE_FAMILY_INET;
            /// \brief
            /// "inet6"
            static const char * const VALUE_FAMILY_INET6;
            /// \brief
            /// "local"
            static const char * const VALUE_FAMILY_LOCAL;
        #if defined (TOOLCHAIN_OS_Linux)
            /// \brief
            /// "netlink"
            static const char * const VALUE_FAMILY_NETLINK;
            /// \brief
            /// "packet"
            static const char * const VALUE_FAMILY_PACKET;
        #elif defined (TOOLCHAIN_OS_OSX)
            /// \brief
            /// "link"
            static const char * const VALUE_FAMILY_LINK;
        #endif // defined (TOOLCHAIN_OS_Linux)
            /// \brief
            /// "Port"
            static const char * const ATTR_PORT;
            /// \brief
            /// "Addr"
            static const char * const ATTR_ADDR;
            /// \brief
            /// "any"
            static const char * const VALUE_ADDR_ANY;
            /// \brief
            /// "loopback"
            static const char * const VALUE_ADDR_LOOPBACK;
            /// \brief
            /// "Path"
            static const char * const ATTR_PATH;
        #if defined (TOOLCHAIN_OS_Linux)
            /// \brief
            /// "Groups"
            static const char * const ATTR_GROUPS;
            /// "Protocol"
            static const char * const ATTR_PROTOCOL;
            /// "AdapterIndex"
            static const char * const ATTR_ADAPTER_INDEX;
        #elif defined (TOOLCHAIN_OS_OSX)
            /// "AdapterIndex"
            static const char * const ATTR_ADAPTER_INDEX;
            /// "AdapterName"
            static const char * const ATTR_ADAPTER_NAME;
        #endif // defined (TOOLCHAIN_OS_Linux)

        #if defined (THEKOGANS_STREAM_HAVE_PUGIXML)
            /// \brief
            /// Convert a string returned by \see{ToString} (below) back to address.
            /// \param[in] addressString String returned by \see{ToString}.
            void FromString (const std::string &addressString);
            /// \brief
            /// Parse an XML represantation of an address.
            /// \param[in] node XML representation of an address.
            /// NOTE: The tag must have the following form:
            /// AF_INET:
            /// <tagName Family = "inet"
            ///          Port = ""
            ///          Addr = ""/>
            /// AF_INET6:
            /// <tagName Family = "inet6"
            ///          Port = ""
            ///          Addr = ""/>
            /// AF_LOCAL:
            /// <tagName Family = "local"
            ///          Path = ""/>
            /// AF_NETLINK:
            /// <tagName Family = "netlink"
            ///          Groups = ""/>
            /// AF_PACKET:
            /// <tagName Family = "packet"
            ///          Protocol = ""
            ///          AdapterIndex = ""
            ///          Addr = ""/>
            /// AF_LINK:
            /// <tagName Family = "link"
            ///          AdapterIndex = ""
            ///          AdapterName = ""
            ///          Addr = ""/>
            /// \param[in] node XML representation of an address.
            void Parse (const pugi::xml_node &node);
        #endif // defined (THEKOGANS_STREAM_HAVE_PUGIXML)
            /// \brief
            /// Return the XML representation of an address.
            /// \param[in] indentationLevel How far to indent the leading tag.
            /// \param[in] tagName The name of the leading tag.
            /// \return XML representation of an address.
            std::string ToString (
                std::size_t indentationLevel = 0,
                const char *tagName = TAG_ADDRESS) const;
        };

        /// \brief
        /// Compare two addresses for equality.
        /// \param[in] address1 First address to compare.
        /// \param[in] address2 Second address to compare.
        /// \return true = equal, false = not equal.
        _LIB_THEKOGANS_STREAM_DECL bool _LIB_THEKOGANS_STREAM_API operator == (
            const Address &address1,
            const Address &address2);
        /// \brief
        /// Compare two addresses for inequality.
        /// \param[in] address1 First address to compare.
        /// \param[in] address2 Second address to compare.
        /// \return true = not equal, false = equal.
        _LIB_THEKOGANS_STREAM_DECL bool _LIB_THEKOGANS_STREAM_API operator != (
            const Address &address1,
            const Address &address2);

    } // namespace stream
} // namespace thekogans

#endif // !defined (__thekogans_stream_Address_h)
