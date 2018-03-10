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

#if !defined (__thekogans_stream_Adapters_h)
#define __thekogans_stream_Adapters_h

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
    #include <net/ethernet.h>
    #if defined (TOOLCHAIN_OS_OSX)
        #include <CoreFoundation/CFRunLoop.h>
    #endif // defined (TOOLCHAIN_OS_OSX)
#endif // defined (TOOLCHAIN_OS_Windows)
#include <string>
#include <list>
#include <map>
#include <ostream>
#include "thekogans/util/Types.h"
#include "thekogans/util/Singleton.h"
#include "thekogans/util/SpinLock.h"
#include "thekogans/util/RefCounted.h"
#include "thekogans/util/JobQueue.h"
#if defined (TOOLCHAIN_OS_Linux) || defined (TOOLCHAIN_OS_OSX)
    #include "thekogans/util/Thread.h"
#endif // defined (TOOLCHAIN_OS_Linux) || defined (TOOLCHAIN_OS_OSX)
#include "thekogans/stream/Config.h"
#include "thekogans/stream/Address.h"
#if defined (TOOLCHAIN_OS_Linux)
    #include "thekogans/stream/UDPSocket.h"
#endif // defined (TOOLCHAIN_OS_Linux)

namespace thekogans {
    namespace stream {

        /// \struct Adapters Adapters.h thekogans/stream/Adapters.h
        ///
        /// \brief
        /// Adapters provides access to physical network adapters. It provides
        /// apis for enumerating adapter addresses as well as listening for
        /// change notifications.
        /// IMPORTANT: Adapters is designed to only deal with ethernet and
        /// wireless adapters that are connected and ready to go. It will
        /// not provide any information about other adapter types or adapters
        /// that are not configured.

        struct _LIB_THEKOGANS_STREAM_DECL Adapters :
            #if defined (TOOLCHAIN_OS_Linux) || defined (TOOLCHAIN_OS_OSX)
                public util::Thread,
            #endif // defined (TOOLCHAIN_OS_Linux) || defined (TOOLCHAIN_OS_OSX)
                public util::Singleton<Adapters, util::SpinLock> {
            /// \struct Adapters::Addresses Adapters.h thekogans/stream/Adapters.h
            ///
            /// \brief
            /// Contains adapter addresses returned by GetAddressesMap.
            struct _LIB_THEKOGANS_STREAM_DECL Addresses {
                /// \brief
                /// Name of adapter.
                std::string name;
                /// \brief
                /// Adapter index.
                util::ui32 index;
                /// \brief
                /// true = adapter supports multicast.
                bool multicast;
                /// \struct Adapters::IPV4 Adapters.h thekogans/stream/Adapters.h
                ///
                /// \brief
                /// IPV4 unicast and broadcast addresses.
                struct IPV4 {
                    /// \brief
                    /// IPV4 unicast address.
                    Address unicast;
                    /// \brief
                    /// IPV4 broadcast address.
                    Address broadcast;

                    /// \brief
                    /// ctor.
                    IPV4 () {}
                    /// \brief
                    /// ctor.
                    /// \param[in] unicast_ IPV4 unicast address.
                    /// \param[in] broadcast_ IPV4 broadcast address.
                    IPV4 (
                        const Address &unicast_,
                        const Address &broadcast_) :
                        unicast (unicast_),
                        broadcast (broadcast_) {}
                };
                /// \brief
                /// List of IPV4 addresses. If the adapter was not
                /// configured for IPV4 it will be empty.
                std::list<IPV4> ipv4;
                /// \brief
                /// List of IPV6 addresses. If the adapter was not
                /// configured for IPV6 it will be empty.
                std::list<Address> ipv6;
                /// \enum
                /// Adapter MAC address length.
                enum {
                #if defined (TOOLCHAIN_OS_Windows)
                    MAC_LENGTH = MAX_ADAPTER_ADDRESS_LENGTH
                #elif defined (TOOLCHAIN_OS_Linux)
                    MAC_LENGTH = ETH_ALEN
                #elif defined (TOOLCHAIN_OS_OSX)
                    MAC_LENGTH = ETHER_ADDR_LEN
                #endif // defined (TOOLCHAIN_OS_Windows)
                };
                /// \brief
                /// Adapter MAC address.
                util::ui8 mac[MAC_LENGTH];

                /// \brief
                /// ctor.
                Addresses () :
                        index (0),
                        multicast (false) {
                    memset (mac, 0, MAC_LENGTH);
                }
                /// \brief
                /// ctor.
                /// \param[in] name_ Name of adapter.
                /// \param[in] index_ Adapter index.
                /// \param[in] multicast_ true = adapter supports multicast.
                Addresses (
                        const std::string &name_,
                        util::ui32 index_,
                        bool multicast_) :
                        name (name_),
                        index (index_),
                        multicast (multicast_) {
                    memset (mac, 0, MAC_LENGTH);
                }

                /// \brief
                /// Check if a given address belongs to this adapter.
                /// \param[in] address Address to check.
                /// \return true = address belongs to this adapter.
                bool Contains (const Address &address) const;

                /// \brief
                /// Dump the contents of Addresses to a given stream.
                /// \param[in] stream Stream to dump the contents to.
                void Dump (std::ostream &stream) const;
            };
            /// \brief
            /// Convenient typedef for std::list<Addresses>.
            typedef std::list<Addresses> AddressesList;
            /// \brief
            /// Convenient typedef for std::map<std::string, Addresses>.
            typedef std::map<std::string, Addresses> AddressesMap;

            /// \struct Adapters::Addresses Adapters.h thekogans/stream/Adapters.h
            ///
            /// \brief
            /// Network change notification event handler. Derive from this
            /// class and call RegisterEventHandler to be notified when network
            /// changes occur.
            struct _LIB_THEKOGANS_STREAM_DECL EventHandler :
                    public virtual util::ThreadSafeRefCounted {
                /// \brief
                /// Convenient typedef for util::ThreadSafeRefCounted::Ptr<EventHandler>.
                typedef util::ThreadSafeRefCounted::Ptr<EventHandler> Ptr;

                /// \brief
                /// dtor.
                virtual ~EventHandler () {}

                /// \brief
                /// Called when a new adapter was added to the network.
                /// \param[in] addresses New adapter addresses.
                virtual void HandleAdapterAdded (
                    const Addresses & /*addresses*/) throw () {}
                /// \brief
                /// Called when an existing adapter was removed from the network.
                /// \param[in] addresses Deleted adapter addresses.
                virtual void HandleAdapterDeleted (
                    const Addresses & /*addresses*/) throw () {}
                /// \brief
                /// Called when an existing adapter was modified.
                /// \param[in] oldAddresses Old adapter addresses.
                /// \param[in] newAddresses New adapter addresses.
                virtual void HandleAdapterChanged (
                    const Addresses & /*oldAddresses*/,
                    const Addresses & /*newAddresses*/) throw () {}
            };

        private:
            /// \brief
            /// Map of current network adapter addresses.
            AddressesMap addressesMap;
            /// \brief
            /// Convenient typedef for std::list<EventHandler::Ptr>.
            typedef std::list<EventHandler::Ptr> EventHandlers;
            /// \brief
            /// List of event handlers to be notied when the network changes.
            EventHandlers eventHandlers;
            /// \brief
            /// Adapters is a global singleton. Access to it must be serialized.
            util::SpinLock spinLock;
        #if defined (TOOLCHAIN_OS_Windows)
            /// \brief
            /// Returned by NotifyIpInterfaceChange to be used with CancelMibChangeNotify2.
            HANDLE handle;
        #elif defined (TOOLCHAIN_OS_Linux)
            /// \brief
            /// Linux netlink socket to listen for network changes.
            UDPSocket::Ptr socket;
        #elif defined (TOOLCHAIN_OS_OSX)
            /// \brief
            /// OS X run loop to use to listen for network changes.
            CFRunLoopRef runLoop;
        #endif // defined (TOOLCHAIN_OS_Windows)
            /// \brief
            /// Used to serialize delivery of network change events.
            util::JobQueue jobQueue;

        public:
            /// \brief
            /// ctor.
            Adapters ();

            /// \brief
            /// Register a network change listener.
            /// \param[in] eventHandler Listener to register.
            void RegisterEventHandler (EventHandler &eventHandler);
            /// \brief
            /// Unregister a network change listener.
            /// \param[in] eventHandler Listener to unregister.
            void UnregisterEventHandler (EventHandler &eventHandler);

            /// \brief
            /// Return a list of current adapter addresses.
            /// \return A list of current adapter addresses.
            AddressesList GetAddressesList ();

        private:
            /// \brief
            /// Used internally to notify listeners of network change events.
            void NotifyEventHandlers ();

        #if defined (TOOLCHAIN_OS_Windows)
            static VOID NETIOAPI_API_ InterfaceChangeCallback (
                PVOID /*CallerContext*/,
                PMIB_IPINTERFACE_ROW Row,
                MIB_NOTIFICATION_TYPE /*NotificationType*/);
        #elif defined (TOOLCHAIN_OS_OSX)
            static void SCDynamicStoreCallBack (
                SCDynamicStoreRef /*store*/,
                CFArrayRef /*changedKeys*/,
                void * /*info*/);
        #endif // defined (TOOLCHAIN_OS_Windows)

            /// \brief
            /// Get all interface addresses.
            /// \param[out] addressesMap Map of addresses to return.
            void GetAddressesMap (AddressesMap &addressesMap) const;

        #if defined (TOOLCHAIN_OS_Linux) || defined (TOOLCHAIN_OS_OSX)
            // util::Thread
            /// \brief
            /// Used on Linux and OS X to listen for network changes.
            virtual void Run () throw ();
        #endif // defined (TOOLCHAIN_OS_Linux) || defined (TOOLCHAIN_OS_OSX)

            /// \brief
            /// Start listening for network change events.
            void StartListening ();
            /// \brief
            /// Stop listening for network change events.
            void StopListening ();

            /// \brief
            /// Adapters is neither copy constructable, nor assignable.
            THEKOGANS_STREAM_DISALLOW_COPY_AND_ASSIGN (Adapters)
        };

    } // namespace stream
} // namespace thekogans

#endif // !defined (__thekogans_stream_Adapters_h)
