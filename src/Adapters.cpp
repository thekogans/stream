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
    #include <ws2def.h>
    #include <ws2ipdef.h>
    #include <iphlpapi.h>
#else // defined (TOOLCHAIN_OS_Windows)
    #include <map>
    #include <net/if.h>
    #include <ifaddrs.h>
    #if defined (TOOLCHAIN_OS_Linux)
        #include <net/if_arp.h>
        #include <linux/rtnetlink.h>
    #elif defined (TOOLCHAIN_OS_OSX)
        #include <net/if_dl.h>
        #include <net/if_types.h>
        #include <SystemConfiguration/SCDynamicStore.h>
    #endif // defined (TOOLCHAIN_OS_Linux)
    #include "thekogans/util/Flags.h"
#endif // defined (TOOLCHAIN_OS_Windows)
#include <cassert>
#include <set>
#include "thekogans/util/Exception.h"
#include "thekogans/util/LoggerMgr.h"
#include "thekogans/util/StringUtils.h"
#include "thekogans/stream/Adapters.h"

namespace thekogans {
    namespace stream {

        THEKOGANS_UTIL_IMPLEMENT_HEAP_WITH_LOCK (AdapterAddresses, util::SpinLock)

        bool AdapterAddresses::Contains (const Address &address) const {
            util::ui16 family = address.GetFamily ();
            if (family == AF_INET) {
                const std::string addressString = address.AddrToString ();
                for (IPV4Addresses::const_iterator
                        it = ipv4.begin (),
                        end = ipv4.end (); it != end; ++it) {
                    if ((*it).unicast.AddrToString () == addressString) {
                        return true;
                    }
                }
            }
            else if (family == AF_INET6) {
                const std::string addressString = address.AddrToString ();
                for (IPV6Addresses::const_iterator
                        it = ipv6.begin (),
                        end = ipv6.end (); it != end; ++it) {
                    if ((*it).AddrToString () == addressString) {
                        return true;
                    }
                }
            }
            // FIXME: Need to account for Windows (use WinPCap).
        #if defined (TOOLCHAIN_OS_Linux)
            else if (family == AF_PACKET) {
                std::vector<util::ui8> addr = address.GetAddrPacket ();
                return addr.size () == util::MAC_LENGTH &&
                    memcmp (mac, addr.data (), addr.size ()) == 0;
            }
        #elif defined (TOOLCHAIN_OS_OSX)
            else if (family == AF_LINK) {
                std::vector<util::ui8> addr = address.GetAddrLink ();
                return addr.size () == util::MAC_LENGTH &&
                    memcmp (mac, addr.data (), addr.size ()) == 0;
            }
        #endif // defined (TOOLCHAIN_OS_Linux)
            return false;
        }

        void AdapterAddresses::Dump (std::ostream &stream) const {
            stream <<
                "Name: " << name << std::endl <<
                "Index: " << index << std::endl <<
                "Multicast: " << util::boolTostring (multicast) << std::endl <<
                "IPV4:\n";
            for (IPV4Addresses::const_iterator
                    it = ipv4.begin (),
                    end = ipv4.end (); it != end; ++it) {
                stream <<
                    "  Unicast:\n" << (*it).unicast.ToString (2) <<
                    "  Broadcast:\n" << (*it).broadcast.ToString (2);
            }
            stream << "IPV6:\n";
            for (IPV6Addresses::const_iterator
                    it = ipv6.begin (),
                    end = ipv6.end (); it != end; ++it) {
                stream << (*it).ToString (1);
            }
            stream << "MAC: " << util::HexEncodeBuffer (mac, util::MAC_LENGTH) << std::endl;
        }

        Adapters::Adapters () :
            #if defined (TOOLCHAIN_OS_Linux) || defined (TOOLCHAIN_OS_OSX)
                Thread ("Adapters"),
            #endif // defined (TOOLCHAIN_OS_Linux) || defined (TOOLCHAIN_OS_OSX)
            #if defined (TOOLCHAIN_OS_Windows)
                handle (0),
            #elif defined (TOOLCHAIN_OS_Linux)
                socket (0),
            #elif defined (TOOLCHAIN_OS_OSX)
                runLoop (0),
            #endif // defined (TOOLCHAIN_OS_Windows)
                addressesMap (GetAddressesMap ()) {}

        AdapterAddressesList Adapters::GetAddressesList () {
            util::LockGuard<util::SpinLock> guard (spinLock);
            AdapterAddressesList addressesList;
            for (AdapterAddressesMap::const_iterator
                    it = addressesMap.begin (),
                    end = addressesMap.end (); it != end; ++it) {
                addressesList.push_back (it->second);
            }
            return addressesList;
        }

        namespace {
            inline bool operator < (
                    const AdapterAddresses &item1,
                    const AdapterAddresses &item2) {
                return item1.name < item2.name;
            }

            inline bool operator != (
                    const AdapterAddresses::IPV4Addresses &item1,
                    const AdapterAddresses::IPV4Addresses &item2) {
                if (item1.size () == item2.size ()) {
                    std::set<std::string> ipv41;
                    for (AdapterAddresses::IPV4Addresses::const_iterator
                            it = item1.begin (),
                            end = item1.end (); it != end; ++it) {
                        ipv41.insert ((*it).unicast.AddrToString ());
                    }
                    std::set<std::string> ipv42;
                    for (AdapterAddresses::IPV4Addresses::const_iterator
                            it = item2.begin (),
                            end = item2.end (); it != end; ++it) {
                        ipv42.insert ((*it).unicast.AddrToString ());
                    }
                    return ipv41 != ipv42;
                }
                return true;
            }

            inline bool operator != (
                    const AdapterAddresses::IPV6Addresses &item1,
                    const AdapterAddresses::IPV6Addresses &item2) {
                if (item1.size () == item2.size ()) {
                    std::set<std::string> ipv61;
                    for (AdapterAddresses::IPV6Addresses::const_iterator
                            it = item1.begin (),
                            end = item1.end (); it != end; ++it) {
                        ipv61.insert ((*it).AddrToString ());
                    }
                    std::set<std::string> ipv62;
                    for (AdapterAddresses::IPV6Addresses::const_iterator
                            it = item2.begin (),
                            end = item2.end (); it != end; ++it) {
                        ipv62.insert ((*it).AddrToString ());
                    }
                    return ipv61 != ipv62;
                }
                return true;
            }

            inline bool operator != (
                    const AdapterAddresses &item1,
                    const AdapterAddresses &item2) {
                return item1.name != item2.name ||
                    item1.index != item2.index ||
                    item1.ipv4 != item2.ipv4 ||
                    item1.ipv6 != item2.ipv6 ||
                    memcmp (item1.mac, item2.mac, util::MAC_LENGTH) != 0;
            }

            struct DiffProcessor {
                AdapterAddressesList added;
                AdapterAddressesList deleted;
                std::list<std::pair<AdapterAddresses::SharedPtr, AdapterAddresses::SharedPtr>> changed;

                inline bool IsEmpty () const {
                    return added.empty () && deleted.empty () && changed.empty ();
                }

                // This function works under the assumption that original and current
                // are related. Since the two maps are snapshots in time of the state
                // of adapters in the system, the assumption is satisfied.
                void Diff (
                        const AdapterAddressesMap &original,
                        const AdapterAddressesMap &current) {
                    AdapterAddressesMap::const_iterator originalBegin = original.begin ();
                    AdapterAddressesMap::const_iterator originalEnd = original.end ();
                    AdapterAddressesMap::const_iterator currentBegin = current.begin ();
                    AdapterAddressesMap::const_iterator currentEnd = current.end ();
                    while (originalBegin != originalEnd && currentBegin != currentEnd) {
                        if (*originalBegin->second < *currentBegin->second) {
                            deleted.push_back ((originalBegin++)->second);
                        }
                        else if (*currentBegin->second < *originalBegin->second) {
                            added.push_back ((currentBegin++)->second);
                        }
                        else if (*originalBegin->second != *currentBegin->second) {
                            changed.push_back (
                                std::pair<AdapterAddresses::SharedPtr, AdapterAddresses::SharedPtr> (
                                    (originalBegin++)->second, (currentBegin++)->second));
                        }
                        else {
                            ++originalBegin;
                            ++currentBegin;
                        }
                    }
                    assert (*originalBegin == *originalEnd || *currentBegin == *currentEnd);
                    while (*originalBegin != *originalEnd) {
                        deleted.push_back ((originalBegin++)->second);
                    }
                    while (*currentBegin != *currentEnd) {
                        added.push_back ((currentBegin++)->second);
                    }
                }
            };
        }

        void Adapters::NotifySubscribers () {
            AdapterAddressesMap newAddressesMap = GetAddressesMap ();
            DiffProcessor diffProcessor;
            diffProcessor.Diff (addressesMap, newAddressesMap);
            if (!diffProcessor.IsEmpty ()) {
                {
                    util::LockGuard<util::SpinLock> guard (spinLock);
                    addressesMap = newAddressesMap;
                }
                for (AdapterAddressesList::const_iterator
                        it = diffProcessor.added.begin (),
                        end = diffProcessor.added.end (); it != end; ++it) {
                    util::Producer<AdaptersEvents>::Produce (
                        std::bind (
                            &AdaptersEvents::OnAdapterAdded,
                            std::placeholders::_1,
                            *it));
                }
                for (AdapterAddressesList::const_iterator
                         it = diffProcessor.deleted.begin (),
                         end = diffProcessor.deleted.end (); it != end; ++it) {
                    util::Producer<AdaptersEvents>::Produce (
                        std::bind (
                            &AdaptersEvents::OnAdapterDeleted,
                            std::placeholders::_1,
                            *it));
                }
                for (std::list<std::pair<AdapterAddresses::SharedPtr, AdapterAddresses::SharedPtr>>::const_iterator
                         it = diffProcessor.changed.begin (),
                         end = diffProcessor.changed.end (); it != end; ++it) {
                    util::Producer<AdaptersEvents>::Produce (
                        std::bind (
                            &AdaptersEvents::OnAdapterChanged,
                            std::placeholders::_1,
                            (*it).first,
                            (*it).second));
                }
            }
        }

    #if defined (TOOLCHAIN_OS_Windows)
        namespace {
            struct AdapterInfo {
                MIB_IF_ROW2 row;

                AdapterInfo (DWORD IfIndex) {
                    memset (&row, 0, sizeof (row));
                    row.InterfaceIndex = IfIndex;
                    NETIO_STATUS rc = GetIfEntry2 (&row);
                    if (rc != NO_ERROR) {
                        THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (rc);
                    }
                }

                inline bool IsConnected () const {
                    // Since we only care about adapters that are up and
                    // ready to send/receive, we need to check all this
                    // state to make sure.
                    // NOTE: This took a while to get 'right' and I'm still
                    // not sure if I got it all (details are hard to come by
                    // and M$ documentation generally sucks). If you're having
                    // notification issues, this is the first place to check.
                    return
                        row.Type != IF_TYPE_SOFTWARE_LOOPBACK &&
                        row.InterfaceAndOperStatusFlags.ConnectorPresent == TRUE &&
                        row.InterfaceAndOperStatusFlags.NotMediaConnected == FALSE &&
                        row.InterfaceAndOperStatusFlags.Paused == FALSE &&
                        row.OperStatus == IfOperStatusUp &&
                        row.MediaConnectState == MediaConnectStateConnected;
                }

                inline bool IsMulticast () const {
                    return row.AccessType == NET_IF_ACCESS_BROADCAST;
                }
            };
        }
    #endif // defined (TOOLCHAIN_OS_Windows)

        AdapterAddressesMap Adapters::GetAddressesMap () const {
            AdapterAddressesMap newAddressesMap;
        #if defined (TOOLCHAIN_OS_Windows)
            DWORD size = 0;
            std::vector<util::ui8> buffer;
            DWORD rc;
            // This loop is necessary to avoid a race between
            // calls to GetAdaptersAddresses.
            do {
                if (size > 0) {
                    buffer.resize (size);
                }
                rc = ::GetAdaptersAddresses (
                    AF_UNSPEC,
                    GAA_FLAG_SKIP_ANYCAST |
                    GAA_FLAG_SKIP_MULTICAST |
                    GAA_FLAG_SKIP_DNS_SERVER,
                    0,
                    (PIP_ADAPTER_ADDRESSES)(size > 0 ? buffer.data () : 0),
                    &size);
            } while (rc == ERROR_BUFFER_OVERFLOW && size > 0);
            if (rc == ERROR_SUCCESS) {
                if (size > 0) {
                    for (PIP_ADAPTER_ADDRESSES
                            ipAdapterAddresses = (PIP_ADAPTER_ADDRESSES)buffer.data ();
                            ipAdapterAddresses != 0; ipAdapterAddresses = ipAdapterAddresses->Next) {
                        AdapterInfo adapterInfo (ipAdapterAddresses->IfIndex);
                        if (adapterInfo.IsConnected ()) {
                            AdapterAddresses::SharedPtr addresses (
                                new AdapterAddresses (
                                    ipAdapterAddresses->AdapterName,
                                    ipAdapterAddresses->IfIndex,
                                    adapterInfo.IsMulticast ()));
                            for (PIP_ADAPTER_UNICAST_ADDRESS
                                    unicastAddress = ipAdapterAddresses->FirstUnicastAddress;
                                    unicastAddress != 0; unicastAddress = unicastAddress->Next) {
                                if (unicastAddress->Address.lpSockaddr->sa_family == AF_INET) {
                                    assert (unicastAddress->Address.iSockaddrLength == sizeof (sockaddr_in));
                                    Addresses::IPV4 ipv4;
                                    memcpy (&ipv4.unicast.in, unicastAddress->Address.lpSockaddr,
                                        unicastAddress->Address.iSockaddrLength);
                                    ipv4.unicast.length = sizeof (sockaddr_in);
                                    if (unicastAddress->OnLinkPrefixLength < 32) {
                                        static const util::ui32 masks[] = {
                                            0xffffffff, 0x7fffffff, 0x3fffffff, 0x1fffffff,
                                            0x0fffffff, 0x07ffffff, 0x03ffffff, 0x01ffffff,
                                            0x00ffffff, 0x007fffff, 0x003fffff, 0x001fffff,
                                            0x000fffff, 0x0007ffff, 0x0003ffff, 0x0001ffff,
                                            0x0000ffff, 0x00007fff, 0x00003fff, 0x00001fff,
                                            0x00000fff, 0x000007ff, 0x000003ff, 0x000001ff,
                                            0x000000ff, 0x0000007f, 0x0000003f, 0x0000001f,
                                            0x0000000f, 0x00000007, 0x00000003, 0x00000001,
                                        };
                                        util::ui32 mask = masks[unicastAddress->OnLinkPrefixLength];
                                        ipv4.broadcast.in.sin_family = AF_INET;
                                        ipv4.broadcast.in.sin_addr.s_addr =
                                            htonl (ntohl (ipv4.unicast.in.sin_addr.s_addr) | mask);
                                        ipv4.broadcast.length = sizeof (sockaddr_in);
                                    }
                                    addresses->ipv4.push_back (ipv4);
                                }
                                else if (unicastAddress->Address.lpSockaddr->sa_family == AF_INET6) {
                                    assert (unicastAddress->Address.iSockaddrLength == sizeof (sockaddr_in6));
                                    Address ipv6;
                                    memcpy (&ipv6.in6,
                                        unicastAddress->Address.lpSockaddr,
                                        unicastAddress->Address.iSockaddrLength);
                                    ipv6.length = sizeof (sockaddr_in6);
                                    addresses->ipv6.push_back (ipv6);
                                }
                            }
                            if (ipAdapterAddresses->PhysicalAddressLength == util::MAC_LENGTH) {
                                memcpy (
                                    addresses->mac,
                                    ipAdapterAddresses->PhysicalAddress,
                                    ipAdapterAddresses->PhysicalAddressLength);
                            }
                            if (!addresses->ipv4.empty () || !addresses->ipv6.empty ()) {
                                newAddressesMap.insert (AddressesMap::value_type (addresses->name, addresses));
                            }
                        }
                    }
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (rc);
            }
        #else // defined (TOOLCHAIN_OS_Windows)
            struct addrs {
                ifaddrs *head;
                addrs () :
                    head (0) {}
                ~addrs () {
                    if (head != 0) {
                        freeifaddrs (head);
                    }
                }
            } addrs;
            if (getifaddrs (&addrs.head) == 0) {
                for (ifaddrs *curr = addrs.head; curr != 0; curr = curr->ifa_next) {
                    if (curr->ifa_name != 0 && curr->ifa_addr != 0 &&
                            (curr->ifa_addr->sa_family == AF_INET ||
                                curr->ifa_addr->sa_family == AF_INET6 ||
                            #if defined (TOOLCHAIN_OS_Linux)
                                curr->ifa_addr->sa_family == AF_PACKET) &&
                            #else // defined (TOOLCHAIN_OS_Linux)
                                curr->ifa_addr->sa_family == AF_LINK) &&
                            #endif // defined (TOOLCHAIN_OS_Linux)
                            util::Flags32 (curr->ifa_flags).Test (IFF_UP) &&
                            util::Flags32 (curr->ifa_flags).Test (IFF_RUNNING) &&
                            !util::Flags32 (curr->ifa_flags).Test (IFF_LOOPBACK)) {
                        AdapterAddressesMap::iterator it = newAddressesMap.find (curr->ifa_name);
                        if (it == newAddressesMap.end ()) {
                            std::pair<AdapterAddressesMap::iterator, bool> result =
                                newAddressesMap.insert (
                                    AdapterAddressesMap::value_type (
                                        curr->ifa_name,
                                        AdapterAddresses::SharedPtr (
                                            new AdapterAddresses (
                                                curr->ifa_name,
                                                if_nametoindex (curr->ifa_name),
                                                util::Flags32 (curr->ifa_flags).Test (IFF_MULTICAST)))));
                            if (result.second) {
                                it = result.first;
                            }
                            else {
                                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                                    "Unable to insert interface: %s", curr->ifa_name);
                            }
                        }
                        if (curr->ifa_addr->sa_family == AF_INET) {
                            AdapterAddresses::IPV4 ipv4;
                            memcpy (&ipv4.unicast.in, curr->ifa_addr, sizeof (sockaddr_in));
                            ipv4.unicast.length = sizeof (sockaddr_in);
                            if (util::Flags32 (curr->ifa_flags).Test (IFF_BROADCAST)) {
                                memcpy (&ipv4.broadcast.in, curr->ifa_broadaddr, sizeof (sockaddr_in));
                                ipv4.broadcast.length = sizeof (sockaddr_in);
                            }
                            it->second->ipv4.push_back (ipv4);
                        }
                        else if (curr->ifa_addr->sa_family == AF_INET6) {
                            Address ipv6;
                            memcpy (&ipv6.in6, curr->ifa_addr, sizeof (sockaddr_in6));
                            ipv6.length = sizeof (sockaddr_in6);
                            it->second->ipv6.push_back (ipv6);
                        }
                    #if defined (TOOLCHAIN_OS_Linux)
                        else if (curr->ifa_addr->sa_family == AF_PACKET) {
                            const sockaddr_ll *addr = (const sockaddr_ll *)curr->ifa_addr;
                            if (addr->sll_hatype == ARPHRD_ETHER && addr->sll_halen == util::MAC_LENGTH) {
                                memcpy (it->second->mac, addr->sll_addr, addr->sll_halen);
                            }
                        }
                    #else // defined (TOOLCHAIN_OS_Linux)
                        else if (curr->ifa_addr->sa_family == AF_LINK) {
                            const sockaddr_dl *addr = (const sockaddr_dl *)curr->ifa_addr;
                            if (addr->sdl_type == IFT_ETHER && addr->sdl_alen == util::MAC_LENGTH) {
                                memcpy (it->second->mac, LLADDR (addr), addr->sdl_alen);
                            }
                        }
                    #endif // defined (TOOLCHAIN_OS_Linux)
                    }
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE);
            }
        #endif // defined (TOOLCHAIN_OS_Windows)
            return addressesMap;
        }

    #if defined (TOOLCHAIN_OS_OSX)
        namespace {
            struct SCDynamicStoreRefDeleter {
                void operator () (SCDynamicStoreRef dynamicStoreRef) {
                    if (dynamicStoreRef != 0) {
                        CFRelease (dynamicStoreRef);
                    }
                }
            };
            typedef std::unique_ptr<const __SCDynamicStore, SCDynamicStoreRefDeleter> SCDynamicStoreRefPtr;

            struct CFStringRefDeleter {
                void operator () (CFStringRef stringRef) {
                    if (stringRef != 0) {
                        CFRelease (stringRef);
                    }
                }
            };
            typedef std::unique_ptr<const __CFString, CFStringRefDeleter> CFStringRefPtr;

            struct CFArrayRefDeleter {
                void operator () (CFArrayRef arrayRef) {
                    if (arrayRef != 0) {
                        CFRelease (arrayRef);
                    }
                }
            };
            typedef std::unique_ptr<const __CFArray, CFArrayRefDeleter> CFArrayRefPtr;

            struct CFRunLoopSourceRefDeleter {
                void operator () (CFRunLoopSourceRef runLoopSourceRef) {
                    if (runLoopSourceRef != 0) {
                        CFRelease (runLoopSourceRef);
                    }
                }
            };
            typedef std::unique_ptr<__CFRunLoopSource, CFRunLoopSourceRefDeleter> CFRunLoopSourceRefPtr;
        }

        void Adapters::SCDynamicStoreCallBack (
                SCDynamicStoreRef /*store*/,
                CFArrayRef /*changedKeys*/,
                void * /*info*/) {
            Adapters::Instance ().NotifySubscribers ();
        }
    #endif // defined (TOOLCHAIN_OS_OSX)

    #if defined (TOOLCHAIN_OS_Linux) || defined (TOOLCHAIN_OS_OSX)
        void Adapters::Run () throw () {
            THEKOGANS_UTIL_TRY {
            #if defined (TOOLCHAIN_OS_Linux)
                socket.Reset (new UDPSocket (AF_NETLINK, SOCK_RAW, NETLINK_ROUTE));
                Address address (AF_NETLINK);
                address.SetGroups (RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR);
                socket->Bind (address);
                char buffer[4096];
                while (socket->Read (buffer, 4096) > 0) {
                    NotifySubscribers ();
                }
                socket.Reset ();
            #else // defined (TOOLCHAIN_OS_Linux)
                SCDynamicStoreContext dynamicStoreContext = {0, this, 0, 0, 0};
                SCDynamicStoreRefPtr dynamicStore (
                    SCDynamicStoreCreate (0,
                        CFSTR ("thekogans::stream"),
                        SCDynamicStoreCallBack,
                        &dynamicStoreContext));
                if (dynamicStore.get () != 0) {
                    // This pattern is "State:/Network/Service/[^/]+/IPv4".
                    CFStringRefPtr ipv4 (
                        SCDynamicStoreKeyCreateNetworkServiceEntity (0,
                            kSCDynamicStoreDomainState,
                            kSCCompAnyRegex,
                            kSCEntNetIPv4));
                    // This pattern is "State:/Network/Service/[^/]+/IPv6".
                    CFStringRefPtr ipv6 (
                        SCDynamicStoreKeyCreateNetworkServiceEntity (0,
                            kSCDynamicStoreDomainState,
                            kSCCompAnyRegex,
                            kSCEntNetIPv6));
                    if (ipv4.get () != 0 && ipv6.get () != 0) {
                        CFStringRef patterns[] = {
                            ipv4.get (),
                            ipv6.get ()
                        };
                        CFArrayRefPtr patternList (
                            CFArrayCreate (0,
                                (const void **)patterns,
                                THEKOGANS_UTIL_ARRAY_SIZE (patterns),
                                &kCFTypeArrayCallBacks));
                        if (patternList.get () != 0) {
                            SCDynamicStoreSetNotificationKeys (dynamicStore.get (), 0, patternList.get ());
                            CFRunLoopSourceRefPtr runLoopSource (
                                SCDynamicStoreCreateRunLoopSource (0, dynamicStore.get (), 0));
                            if (runLoopSource.get () != 0) {
                                runLoop = CFRunLoopGetCurrent ();
                                CFRunLoopAddSource (runLoop, runLoopSource.get (), kCFRunLoopDefaultMode);
                                CFRunLoopRun ();
                                CFRunLoopRemoveSource (runLoop, runLoopSource.get (), kCFRunLoopDefaultMode);
                                runLoop = 0;
                            }
                            else {
                                THEKOGANS_UTIL_THROW_SC_ERROR_CODE_EXCEPTION (SCError ());
                            }
                        }
                        else {
                            THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                                THEKOGANS_UTIL_OS_ERROR_CODE_ENOMEM);
                        }
                    }
                    else {
                        THEKOGANS_UTIL_THROW_SC_ERROR_CODE_EXCEPTION (SCError ());
                    }
                }
                else {
                    THEKOGANS_UTIL_THROW_SC_ERROR_CODE_EXCEPTION (SCError ());
                }
            #endif // defined (TOOLCHAIN_OS_Linux)
            }
            THEKOGANS_UTIL_CATCH_AND_LOG_SUBSYSTEM (THEKOGANS_STREAM)
        }
    #endif // defined (TOOLCHAIN_OS_Linux) || defined (TOOLCHAIN_OS_OSX)

    #if defined (TOOLCHAIN_OS_Windows)
        namespace {
        #if defined (THEKOGANS_STREAM_CONFIG_Debug)
            std::string IfTypeTostring (util::ui32 ifType) {
                return
                    ifType == 1 ? "IF_TYPE_OTHER" :
                    ifType == 6 ? "IF_TYPE_ETHERNET_CSMACD" :
                    ifType == 9 ? "IF_TYPE_ISO88025_TOKENRING" :
                    ifType == 23 ? "IF_TYPE_PPP" :
                    ifType == 24 ? "IF_TYPE_SOFTWARE_LOOPBACK" :
                    ifType == 37 ? "IF_TYPE_ATM" :
                    ifType == 71 ? "IF_TYPE_IEEE80211" :
                    ifType == 131 ? "IF_TYPE_TUNNEL" :
                    ifType == 144 ? "IF_TYPE_IEEE1394" :
                    util::FormatString ("Unknown ifType: %u", ifType);
            }

            std::string NL_ROUTER_DISCOVERY_BEHAVIORTostring (
                    const NL_ROUTER_DISCOVERY_BEHAVIOR &routerDiscoveryBehavior) {
                return
                    routerDiscoveryBehavior == 0 ? "RouterDiscoveryDisabled" :
                    routerDiscoveryBehavior == 1 ? "RouterDiscoveryEnabled" :
                    routerDiscoveryBehavior == 2 ? "RouterDiscoveryDhcp" :
                    routerDiscoveryBehavior == -1 ? "RouterDiscoveryUnchanged" :
                    util::FormatString ("Unknown routerDiscoveryBehavior: %d", routerDiscoveryBehavior);
            }

            std::string NL_LINK_LOCAL_ADDRESS_BEHAVIORTostring (
                    const NL_LINK_LOCAL_ADDRESS_BEHAVIOR &linkLocalAddressBehavior) {
                return
                    linkLocalAddressBehavior == 0 ? "LinkLocalAlwaysOff" :
                    linkLocalAddressBehavior == 1 ? "LinkLocalDelayed" :
                    linkLocalAddressBehavior == 2 ? "LinkLocalAlwaysOn" :
                    linkLocalAddressBehavior == -1 ? "LinkLocalUnchanged" :
                    util::FormatString ("Unknown linkLocalAddressBehavior: %d", linkLocalAddressBehavior);
            }

            std::string ListZoneIndices (const ULONG *ZoneIndices) {
                std::string zoneIndices = util::ui32Tostring (ZoneIndices[0]);
                for (util::ui32 i = 1; i < ScopeLevelCount; ++i) {
                    zoneIndices += ", " + util::ui32Tostring (ZoneIndices[i]);
                }
                return zoneIndices;
            }

            std::string NL_INTERFACE_OFFLOAD_RODTostring (
                    const NL_INTERFACE_OFFLOAD_ROD rod) {
                return util::FormatString (
                    "    NlChecksumSupported: %s\n"
                    "    NlOptionsSupported: %s\n"
                    "    TlDatagramChecksumSupported: %s\n"
                    "    TlStreamChecksumSupported: %s\n"
                    "    TlStreamOptionsSupported: %s\n"
                    "    FastPathCompatible: %s\n"
                    "    TlLargeSendOffloadSupported: %s\n"
                    "    TlGiantSendOffloadSupported: %s\n",
                    rod.NlChecksumSupported == TRUE ? "true" : "false",
                    rod.NlOptionsSupported == TRUE ? "true" : "false",
                    rod.TlDatagramChecksumSupported == TRUE ? "true" : "false",
                    rod.TlStreamChecksumSupported == TRUE ? "true" : "false",
                    rod.TlStreamOptionsSupported == TRUE ? "true" : "false",
                    rod.FastPathCompatible == TRUE ? "true" : "false",
                    rod.TlLargeSendOffloadSupported == TRUE ? "true" : "false",
                    rod.TlGiantSendOffloadSupported == TRUE ? "true" : "false");
            }

            void LogMIB_IPINTERFACE_ROW (MIB_IPINTERFACE_ROW &row) {
                GetIpInterfaceEntry (&row);
                THEKOGANS_UTIL_LOG_SUBSYSTEM_DEVELOPMENT (
                    THEKOGANS_STREAM,
                    "MIB_IPINTERFACE_ROW:\n"
                    "  Family: %s\n"
                    "  InterfaceLuid: NetLuidIndex: " THEKOGANS_UTIL_UI32_FORMAT ", IfType: %s\n"
                    "  InterfaceIndex: " THEKOGANS_UTIL_UI32_FORMAT "\n"
                    "  MaxReassemblySize: " THEKOGANS_UTIL_UI32_FORMAT "\n"
                    "  InterfaceIdentifier: " THEKOGANS_UTIL_UI64_FORMAT "\n"
                    "  MinRouterAdvertisementInterval: " THEKOGANS_UTIL_UI32_FORMAT "\n"
                    "  MaxRouterAdvertisementInterval: " THEKOGANS_UTIL_UI32_FORMAT "\n"
                    "  AdvertisingEnabled: %s\n"
                    "  ForwardingEnabled: %s\n"
                    "  WeakHostSend: %s\n"
                    "  WeakHostReceive: %s\n"
                    "  UseAutomaticMetric: %s\n"
                    "  UseNeighborUnreachabilityDetection: %s\n"
                    "  ManagedAddressConfigurationSupported: %s\n"
                    "  OtherStatefulConfigurationSupported: %s\n"
                    "  AdvertiseDefaultRoute: %s\n"
                    "  RouterDiscoveryBehavior: %s\n"
                    "  DadTransmits: " THEKOGANS_UTIL_UI32_FORMAT "\n"
                    "  BaseReachableTime: " THEKOGANS_UTIL_UI32_FORMAT "\n"
                    "  RetransmitTime: " THEKOGANS_UTIL_UI32_FORMAT "\n"
                    "  PathMtuDiscoveryTimeout: " THEKOGANS_UTIL_UI32_FORMAT "\n"
                    "  LinkLocalAddressBehavior: %s\n"
                    "  LinkLocalAddressTimeout: " THEKOGANS_UTIL_UI32_FORMAT "\n"
                    "  ZoneIndices: %s\n"
                    "  SitePrefixLength: " THEKOGANS_UTIL_UI32_FORMAT "\n"
                    "  Metric: " THEKOGANS_UTIL_UI32_FORMAT "\n"
                    "  NlMtu: " THEKOGANS_UTIL_UI32_FORMAT "\n"
                    "  Connected: %s\n"
                    "  SupportsWakeUpPatterns: %s\n"
                    "  SupportsNeighborDiscovery: %s\n"
                    "  SupportsRouterDiscovery: %s\n"
                    "  ReachableTime: " THEKOGANS_UTIL_UI32_FORMAT "\n"
                    "  TransmitOffload:\n%s"
                    "  ReceiveOffload:\n%s"
                    "  DisableDefaultRoutes: %s\n",
                    Address::FamilyToString (row.Family).c_str (),
                    row.InterfaceLuid.Info.NetLuidIndex, IfTypeTostring (row.InterfaceLuid.Info.IfType).c_str (),
                    row.InterfaceIndex,
                    row.MaxReassemblySize,
                    row.InterfaceIdentifier,
                    row.MinRouterAdvertisementInterval,
                    row.MaxRouterAdvertisementInterval,
                    row.AdvertisingEnabled == TRUE ? "true" : "false",
                    row.ForwardingEnabled == TRUE ? "true" : "false",
                    row.WeakHostSend == TRUE ? "true" : "false",
                    row.WeakHostReceive == TRUE ? "true" : "false",
                    row.UseAutomaticMetric == TRUE ? "true" : "false",
                    row.UseNeighborUnreachabilityDetection == TRUE ? "true" : "false",
                    row.ManagedAddressConfigurationSupported == TRUE ? "true" : "false",
                    row.OtherStatefulConfigurationSupported == TRUE ? "true" : "false",
                    row.AdvertiseDefaultRoute == TRUE ? "true" : "false",
                    NL_ROUTER_DISCOVERY_BEHAVIORTostring (row.RouterDiscoveryBehavior).c_str (),
                    row.DadTransmits,
                    row.BaseReachableTime,
                    row.RetransmitTime,
                    row.PathMtuDiscoveryTimeout,
                    NL_LINK_LOCAL_ADDRESS_BEHAVIORTostring (row.LinkLocalAddressBehavior).c_str (),
                    row.LinkLocalAddressTimeout,
                    ListZoneIndices (row.ZoneIndices).c_str (),
                    row.SitePrefixLength,
                    row.Metric,
                    row.NlMtu,
                    row.Connected == TRUE ? "true" : "false",
                    row.SupportsWakeUpPatterns == TRUE ? "true" : "false",
                    row.SupportsNeighborDiscovery == TRUE ? "true" : "false",
                    row.SupportsRouterDiscovery == TRUE ? "true" : "false",
                    row.ReachableTime,
                    NL_INTERFACE_OFFLOAD_RODTostring (row.TransmitOffload).c_str (),
                    NL_INTERFACE_OFFLOAD_RODTostring (row.ReceiveOffload).c_str (),
                    row.DisableDefaultRoutes == TRUE ? "true" : "false");
            }
        #endif // defined (THEKOGANS_STREAM_CONFIG_Debug)
        }

        VOID NETIOAPI_API_ Adapters::InterfaceChangeCallback (
                PVOID /*CallerContext*/,
                PVOID /*PMIB_IPINTERFACE_ROW*/ Row,
                MIB_NOTIFICATION_TYPE /*NotificationType*/) {
        #if defined (THEKOGANS_STREAM_CONFIG_Debug)
            LogMIB_IPINTERFACE_ROW (*(PMIB_IPINTERFACE_ROW)Row);
        #endif // defined (THEKOGANS_STREAM_CONFIG_Debug)
            Adapters::Instance ().NotifySubscribers ();
        }
    #endif // defined (TOOLCHAIN_OS_Windows)

        void Adapters::OnSubscribe (
                util::Subscriber<AdaptersEvents> & /*subscriber*/,
                util::Producer<AdaptersEvents>::EventDeliveryPolicy::SharedPtr /*eventDeliveryPolicy*/) {
            if (util::Producer<AdaptersEvents>::GetSubscriberCount () == 1) {
                addressesMap = GetAddressesMap ();
            #if defined (TOOLCHAIN_OS_Windows)
                if (handle == 0) {
                    typedef VOID (NETIOAPI_API_ *INTERFACE_CHANGE_CALLBACK) (
                        PVOID,
                        PMIB_IPINTERFACE_ROW,
                        MIB_NOTIFICATION_TYPE);
                    DWORD rc = NotifyIpInterfaceChange (AF_UNSPEC,
                        (INTERFACE_CHANGE_CALLBACK)InterfaceChangeCallback, 0, FALSE, &handle);
                    if (rc != NO_ERROR) {
                        THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (rc);
                    }
                }
            #elif defined (TOOLCHAIN_OS_Linux)
                if (socket.Get () == 0) {
                    Create (THEKOGANS_UTIL_NORMAL_THREAD_PRIORITY);
                }
            #elif defined (TOOLCHAIN_OS_OSX)
                if (runLoop == 0) {
                    Create (THEKOGANS_UTIL_NORMAL_THREAD_PRIORITY);
                }
            #endif // defined (TOOLCHAIN_OS_Windows)
            }
        }

        void Adapters::OnUnsubscribe (util::Subscriber<AdaptersEvents> & /*subscriber*/) {
            if (util::Producer<AdaptersEvents>::GetSubscriberCount () == 0) {
            #if defined (TOOLCHAIN_OS_Windows)
                if (handle != 0) {
                    if (CancelMibChangeNotify2 (handle) != NO_ERROR) {
                        THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                            THEKOGANS_UTIL_OS_ERROR_CODE);
                    }
                    handle = 0;
                }
            #elif defined (TOOLCHAIN_OS_Linux)
                if (socket.Get () != 0) {
                    socket->Close ();
                    Wait ();
                }
            #elif defined (TOOLCHAIN_OS_OSX)
                if (runLoop != 0) {
                    CFRunLoopStop (runLoop);
                    Wait ();
                }
            #endif // defined (TOOLCHAIN_OS_Windows)
            }
        }

    } // namespace stream
} // namespace thekogans
