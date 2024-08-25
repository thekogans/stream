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

#include "thekogans/util/Exception.h"
#include "thekogans/util/LoggerMgr.h"
#include "thekogans/stream/NamedPipe.h"
#include "thekogans/stream/namedpipeecho/server/Options.h"
#include "thekogans/stream/namedpipeecho/server/Server.h"

namespace thekogans {
    namespace stream {
        namespace namedpipeecho {
            namespace server {

                void Server::Start () {
                    CreateServerNamedPipe ();
                }

                void Server::Stop () {
                    util::Subscriber<stream::StreamEvents>::Unsubscribe ();
                    util::Subscriber<stream::NamedPipeEvents>::Unsubscribe ();
                    serverNamedPipe.Reset ();
                    connections.clear ();
                }

                void Server::OnStreamError (
                        Stream::SharedPtr stream,
                        const util::Exception &exception) throw () {
                    THEKOGANS_UTIL_LOG_ERROR ("%s\n", exception.Report ().c_str ());
                    RemoveConnection (stream);
                }

                void Server::OnStreamDisconnect (Stream::SharedPtr stream) throw () {
                    THEKOGANS_UTIL_LOG_INFO ("%s\n", "Connection closed.");
                    RemoveConnection (stream);
                }

                void Server::OnStreamRead (
                        Stream::SharedPtr stream,
                        util::Buffer::SharedPtr buffer) throw () {
                    // We're an echo server.
                    stream->Write (buffer);
                }

                void Server::OnNamedPipeConnected (NamedPipe::SharedPtr namedPipe) throw () {
                    THEKOGANS_UTIL_LOG_INFO ("%s\n", "Received connection request.");
                    // Initiate an async read to listen for client requests.
                    namedPipe->Read ();
                    connections.push_back (namedPipe);
                    CreateServerNamedPipe ();
                }

                void Server::RemoveConnection (Stream::SharedPtr stream) {
                    std::vector<Stream::SharedPtr>::iterator it =
                        std::find (connections.begin (), connections.end (), stream);
                    if (it != connections.end ()) {
                        NamedPipe::SharedPtr namedPipe = stream;
                        util::Subscriber<stream::StreamEvents>::Unsubscribe (*namedPipe);
                        util::Subscriber<stream::NamedPipeEvents>::Unsubscribe (*namedPipe);
                        connections.erase (it);
                    }
                }

                void Server::CreateServerNamedPipe () {
                    serverNamedPipe = NamedPipe::CreateServerNamedPipe (
                        Options::Instance ()->address);
                    // Setup async notifications.
                    // NOTE: We use the default EventDeliveryPolicy (ImmediateEventDeliveryPolicy).
                    // The reason for this is explained in \see{Stream}.
                    util::Subscriber<stream::StreamEvents>::Subscribe (*serverNamedPipe);
                    util::Subscriber<stream::NamedPipeEvents>::Subscribe (*serverNamedPipe);
                    // We're open for business. Start listening for client connections.
                    serverNamedPipe->Connect ();
                }

            } // namespace server
        } // namespace namedpipeecho
    } // namespace stream
} // namespace thekogans

#endif // defined (TOOLCHAIN_OS_Windows)
