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

#include "thekogans/util/Exception.h"
#include "thekogans/util/LoggerMgr.h"
#include "thekogans/stream/UDPSocket.h"
#include "thekogans/udpecho/server/Server.h"

namespace thekogans {
    namespace stream {
        namespace udpecho {
            namespace server {

                void Server::Start (
                        const std::list<Address> &addresses,
                        bool message,
                        util::ui32 maxPacketSize,
                        util::i32 priority) {
                    if (!addresses.empty ()) {
                        if (maxPacketSize > 0 && maxPacketSize <= DEFAULT_MAX_PACKET_SIZE) {
                            if (done) {
                                eventQueue.reset (new AsyncIoEventQueue ());
                                for (std::list<Address>::const_iterator
                                        it = addresses.begin (),
                                        end = addresses.end (); it != end; ++it) {
                                    UDPSocket::Ptr udpSocket (new UDPSocket (*it));
                                    udpSocket->SetSendBufferSize (maxPacketSize);
                                    udpSocket->SetReceiveBufferSize (maxPacketSize);
                                    if (message) {
                                        udpSocket->SetRecvPktInfo (true);
                                    }
                                    eventQueue->AddStream (*udpSocket, *this, maxPacketSize);
                                    THEKOGANS_UTIL_LOG_INFO ("Listening on: %s:%u\n",
                                        (*it).AddrToString ().c_str (), (*it).GetPort ());
                                }
                                done = false;
                                Create (priority);
                            }
                            else {
                                THEKOGANS_UTIL_LOG_WARNING (
                                    "%s\n", "Server is already running.");
                            }
                        }
                        else {
                            THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                                "maxPacketSize out of bounds %u (%u, %u]",
                                maxPacketSize, 0, DEFAULT_MAX_PACKET_SIZE);
                        }
                    }
                    else {
                        THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                            "%s", "Must supply at least one address to listen on.");
                    }
                }

                void Server::Stop () {
                    if (!done) {
                        done = true;
                        jobQueue.Stop ();
                        eventQueue->Break ();
                        Wait ();
                        eventQueue.reset ();
                    }
                    else {
                        THEKOGANS_UTIL_LOG_WARNING (
                            "%s\n", "Server is not running.");
                    }
                }

                void Server::Run () throw () {
                    while (!done) {
                        THEKOGANS_UTIL_TRY {
                            eventQueue->WaitForEvents ();
                        }
                        THEKOGANS_UTIL_CATCH_AND_LOG
                    }
                    THEKOGANS_UTIL_LOG_INFO ("%s\n", "Server thread is exiting.");
                }

                void Server::HandleStreamError (
                        Stream &stream,
                        const util::Exception &exception) throw () {
                    THEKOGANS_UTIL_LOG_ERROR ("%s\n", exception.Report ().c_str ());
                }

                void Server::HandleUDPSocketReadFrom (
                        UDPSocket &udpSocket,
                        util::Buffer::UniquePtr buffer,
                        const Address &address) throw () {
                    THEKOGANS_UTIL_LOG_DEBUG (
                        "Received buffer from: %s:%u\n",
                        address.AddrToString ().c_str (),
                        address.GetPort ());
                    THEKOGANS_UTIL_TRY {
                        if (buffer->GetDataAvailableForReading () != 0) {
                            struct WriteJob : public util::JobQueue::Job {
                                UDPSocket::Ptr udpSocket;
                                util::Buffer::UniquePtr buffer;
                                Address address;
                                WriteJob (
                                    UDPSocket &udpSocket_,
                                    util::Buffer::UniquePtr buffer_,
                                    const Address &address_) :
                                    udpSocket (&udpSocket_),
                                    buffer (std::move (buffer_)),
                                    address (address_) {}
                                // util::JobQueue::Job
                                virtual void Execute (volatile const bool &done) throw () {
                                    if (!done) {
                                        THEKOGANS_UTIL_TRY {
                                            udpSocket->WriteBufferTo (std::move (buffer), address);
                                        }
                                        THEKOGANS_UTIL_CATCH_AND_LOG
                                    }
                                }
                            };
                            jobQueue.Enq (
                                *util::JobQueue::Job::Ptr (
                                    new WriteJob (udpSocket, std::move (buffer), address)));
                        }
                    }
                    THEKOGANS_UTIL_CATCH_AND_LOG
                }

                void Server::HandleUDPSocketWriteTo (
                        UDPSocket &udpSocket,
                        util::Buffer::UniquePtr buffer,
                        const Address &address) throw () {
                    THEKOGANS_UTIL_LOG_DEBUG (
                        "Sent buffer to: %s:%u\n",
                        address.AddrToString ().c_str (),
                        address.GetPort ());
                }

                void Server::HandleUDPSocketReadMsg (
                        UDPSocket &udpSocket,
                        util::Buffer::UniquePtr buffer,
                        const Address &from,
                        const Address &to) throw () {
                    THEKOGANS_UTIL_LOG_DEBUG (
                        "Received buffer from: %s:%u to: %s:%u\n",
                        from.AddrToString ().c_str (),
                        from.GetPort (),
                        to.AddrToString ().c_str (),
                        to.GetPort ());
                    THEKOGANS_UTIL_TRY {
                        if (buffer->GetDataAvailableForReading () != 0) {
                            struct WriteJob : public util::JobQueue::Job {
                                UDPSocket::Ptr udpSocket;
                                util::Buffer::UniquePtr buffer;
                                Address from;
                                Address to;
                                WriteJob (
                                    UDPSocket &udpSocket_,
                                    util::Buffer::UniquePtr buffer_,
                                    const Address &from_,
                                    const Address &to_) :
                                    udpSocket (&udpSocket_),
                                    buffer (std::move (buffer_)),
                                    from (from_),
                                    to (to_) {}
                                // util::JobQueue::Job
                                virtual void Execute (volatile const bool &done) throw () {
                                    if (!done) {
                                        THEKOGANS_UTIL_TRY {
                                            udpSocket->WriteBufferMsg (std::move (buffer), from, to);
                                        }
                                        THEKOGANS_UTIL_CATCH_AND_LOG
                                    }
                                }
                            };
                            jobQueue.Enq (
                                *util::JobQueue::Job::Ptr (
                                    new WriteJob (udpSocket, std::move (buffer), to, from)));
                        }
                    }
                    THEKOGANS_UTIL_CATCH_AND_LOG
                }

                void Server::HandleUDPSocketWriteMsg (
                        UDPSocket &udpSocket,
                        util::Buffer::UniquePtr buffer,
                        const Address &from,
                        const Address &to) throw () {
                    THEKOGANS_UTIL_LOG_DEBUG (
                        "Sent buffer from: %s:%u to: %s:%u\n",
                        from.AddrToString ().c_str (),
                        from.GetPort (),
                        to.AddrToString ().c_str (),
                        to.GetPort ());
                }

            } // namespace server
        } // namespace udpecho
    } // namespace stream
} // namespace thekogans
