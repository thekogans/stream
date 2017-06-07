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

#include "thekogans/util/HRTimer.h"
#include "thekogans/util/Exception.h"
#include "thekogans/util/LoggerMgr.h"
#include "thekogans/stream/ServerUDPSocket.h"
#include "thekogans/serverudpecho/server/Server.h"

namespace thekogans {
    namespace stream {
        namespace serverudpecho {
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
                                eventQueue->SetTimeoutPolicy (
                                    AsyncIoEventQueue::TimeoutPolicy::UniquePtr (
                                        new AsyncIoEventQueue::DefaultTimeoutPolicy (*eventQueue)));
                                for (std::list<Address>::const_iterator
                                        it = addresses.begin (),
                                        end = addresses.end (); it != end; ++it) {
                                    ServerUDPSocket::Ptr serverUDPSocket (
                                        new ServerUDPSocket (*it, maxPacketSize));
                                    serverUDPSocket->SetReceiveBufferSize (maxPacketSize);
                                    eventQueue->AddStream (*serverUDPSocket, *this, maxPacketSize);
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
                    THEKOGANS_UTIL_LOG_INFO (
                        "%s\n", "Server thread is exiting.");
                }

                void Server::HandleStreamError (
                        Stream &stream,
                        const util::Exception &exception) throw () {
                    THEKOGANS_UTIL_TRY {
                        if (exception.GetErrorCode () == THEKOGANS_UTIL_OS_ERROR_CODE_TIMEOUT) {
                            THEKOGANS_UTIL_LOG_INFO ("%s\n", "Client disconnected.");
                            eventQueue->DeleteStream (stream);
                        }
                        else {
                            THEKOGANS_UTIL_LOG_ERROR (
                                "%s\n", exception.Report ().c_str ());
                        }
                    }
                    THEKOGANS_UTIL_CATCH_AND_LOG
                }

                void Server::HandleServerUDPSocketConnection (
                        ServerUDPSocket &serverUDPSocket,
                        ServerUDPSocket::Connection::UniquePtr connection) throw () {
                    THEKOGANS_UTIL_LOG_INFO ("%s\n", "Received connection request.");
                    THEKOGANS_UTIL_TRY {
                        connection->udpSocket->SetReadTimeout (
                            util::TimeSpec::FromSeconds (5));
                        eventQueue->AddStream (
                            *connection->udpSocket,
                            *this,
                            serverUDPSocket.GetReceiveBufferSize ());
                        HandleStreamRead (*connection->udpSocket, std::move (connection->buffer));
                    }
                    THEKOGANS_UTIL_CATCH_AND_LOG
                }

                void Server::HandleStreamRead (
                        Stream &stream,
                        util::Buffer::UniquePtr buffer) throw () {
                    THEKOGANS_UTIL_TRY {
                        struct WriteJob : public util::JobQueue::Job {
                            Stream::Ptr stream;
                            util::Buffer::UniquePtr buffer;
                            WriteJob (
                                Stream &stream_,
                                util::Buffer::UniquePtr buffer_) :
                                stream (&stream_),
                                buffer (std::move (buffer_)) {}
                            // util::JobQueue::Job
                            virtual void Execute (volatile const bool &done) throw () {
                                if (!done) {
                                    THEKOGANS_UTIL_TRY {
                                        stream->WriteBuffer (std::move (buffer));
                                    }
                                    THEKOGANS_UTIL_CATCH_AND_LOG
                                }
                            }
                        };
                        util::JobQueue::Job::UniquePtr job (
                            new WriteJob (stream, std::move (buffer)));
                        jobQueue.Enq (std::move (job));
                    }
                    THEKOGANS_UTIL_CATCH_AND_LOG
                }

            } // namespace server
        } // namespace serverudpecho
    } // namespace stream
} // namespace thekogans
