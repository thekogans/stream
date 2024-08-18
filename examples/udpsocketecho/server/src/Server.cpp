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
#include "thekogans/stream/udpecho/server/Options.h"
#include "thekogans/stream/udpecho/server/Server.h"

namespace thekogans {
    namespace stream {
        namespace udpecho {
            namespace server {

                void Server::Start () {
                    // Create a listening socket.
                    serverSocket.Reset (new stream::UDPSocket);
                    // Setup async notifications.
                    // NOTE: We use the default EventDeliveryPolicy (ImmediateEventDeliveryPolicy).
                    // The reason for this is explained in \see{Stream}.
                    util::Subscriber<stream::StreamEvents>::Subscribe (*serverSocket);
                    util::Subscriber<stream::UDPSocketEvents>::Subscribe (*serverSocket);
                    serverSocket->SetSendBufferSize (Options::Instance ()->blockSize);
                    serverSocket->SetReceiveBufferSize (Options::Instance ()->blockSize);
                    // Bind to the given address.
                    serverSocket->Bind (Options::Instance ()->address);
                    if (Options::Instance ()->message) {
                        serverSocket->SetRecvPktInfo (true);
                        serverSocket->ReadMsg (Options::Instance ()->blockSize);
                    }
                    else {
                        serverSocket->ReadFrom (Options::Instance ()->blockSize);
                    }
                }

                void Server::Stop () {
                    util::Subscriber<stream::StreamEvents>::Unsubscribe ();
                    util::Subscriber<stream::UDPSocketEvents>::Unsubscribe ();
                    serverSocket.Reset ();
                }

                void Server::OnStreamError (
                        Stream::SharedPtr stream,
                        util::Exception::SharedPtr exception) throw () {
                    THEKOGANS_UTIL_LOG_ERROR ("%s\n", exception->Report ().c_str ());
                }

                void Server::OnUDPSocketReadFrom (
                        UDPSocket::SharedPtr udpSocket,
                        util::Buffer::SharedPtr buffer,
                        Address address) throw () {
                    THEKOGANS_UTIL_LOG_DEBUG (
                        "OnUDPSocketReadFrom: %s:%u (%u bytes)\n",
                        address.AddrToString ().c_str (),
                        address.GetPort (),
                        buffer->GetDataAvailableForReading ());
                    udpSocket->WriteTo (buffer, address);
                }

                void Server::OnUDPSocketReadMsg (
                        UDPSocket::SharedPtr udpSocket,
                        util::Buffer::SharedPtr buffer,
                        Address from,
                        Address to) throw () {
                    THEKOGANS_UTIL_LOG_DEBUG (
                        "OnUDPSocketReadMsg: %s:%u to: %s:%u (%u bytes)\n",
                        from.AddrToString ().c_str (),
                        from.GetPort (),
                        to.AddrToString ().c_str (),
                        to.GetPort (),
                        buffer->GetDataAvailableForReading ());
                    udpSocket->WriteMsg (buffer, to, from);
                }

            } // namespace server
        } // namespace udpecho
    } // namespace stream
} // namespace thekogans
