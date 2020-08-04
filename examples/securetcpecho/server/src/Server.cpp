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

#include <pugixml/pugixml.hpp>
#include "thekogans/util/Exception.h"
#include "thekogans/util/LoggerMgr.h"
#include "thekogans/stream/ServerSecureTCPSocket.h"
#include "thekogans/stream/securetcpecho/server/Server.h"

namespace thekogans {
    namespace stream {
        namespace securetcpecho {
            namespace server {

                void Server::Start (
                        const std::string &path,
                        util::i32 priority,
                        bool useWriteQueue_) {
                    if (done) {
                        if (!path.empty ()) {
                            pugi::xml_document document;
                            pugi::xml_parse_result result =
                                document.load_file (path.c_str ());
                            if (result) {
                                eventQueue.reset (new stream::AsyncIoEventQueue ());
                                eventQueue->AddStream (
                                    *stream::ServerSecureTCPSocket::Context (
                                        document.document_element ()).CreateStream (),
                                    *this);
                                done = false;
                                Create (priority);
                                useWriteQueue = useWriteQueue_;
                            }
                            else {
                                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                                    "%s", result.description ());
                            }
                        }
                        else {
                            THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                                "%s", "Must supply path for ServerSecureTCPSocket configuration.");
                        }
                    }
                    else {
                        THEKOGANS_UTIL_LOG_WARNING (
                            "%s\n", "Server is already running.");
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
                        stream::Stream &stream,
                        const util::Exception &exception) throw () {
                    THEKOGANS_UTIL_LOG_ERROR ("%s\n", exception.Report ().c_str ());
                    THEKOGANS_UTIL_TRY {
                        eventQueue->DeleteStream (stream);
                    }
                    THEKOGANS_UTIL_CATCH_AND_LOG
                }

                void Server::HandleServerSecureTCPSocketConnection (
                        stream::ServerSecureTCPSocket &serverSecureTCPSocket,
                        stream::SecureTCPSocket::Ptr connection) throw () {
                    THEKOGANS_UTIL_LOG_INFO ("%s\n", "Received connection request.");
                    THEKOGANS_UTIL_TRY {
                        eventQueue->AddStream (*connection, *this);
                        connection->SessionAccept (
                            serverSecureTCPSocket.ctx.get (),
                            serverSecureTCPSocket.sessionInfo);
                    }
                    THEKOGANS_UTIL_CATCH_AND_LOG
                }

                void Server::HandleStreamDisconnect (stream::Stream &stream) throw () {
                    THEKOGANS_UTIL_LOG_INFO ("%s\n", "Connection closed.");
                    THEKOGANS_UTIL_TRY {
                        eventQueue->DeleteStream (stream);
                    }
                    THEKOGANS_UTIL_CATCH_AND_LOG
                }

                void Server::HandleStreamRead (
                        stream::Stream &stream,
                        util::Buffer buffer) throw () {
                    if (useWriteQueue) {
                        THEKOGANS_UTIL_TRY {
                            struct WriteJob : public util::RunLoop::Job {
                                stream::Stream::Ptr stream;
                                util::Buffer buffer;
                                WriteJob (
                                    stream::Stream &stream_,
                                    util::Buffer buffer_) :
                                    stream (&stream_),
                                    buffer (std::move (buffer_)) {}
                                // util::RunLoop::Job
                                virtual void Execute (const std::atomic<bool> &done) throw () {
                                    if (!ShouldStop (done)) {
                                        THEKOGANS_UTIL_TRY {
                                            stream->WriteBuffer (std::move (buffer));
                                        }
                                        THEKOGANS_UTIL_CATCH_AND_LOG
                                    }
                                }
                            };
                            jobQueue.EnqJob (
                                util::RunLoop::Job::Ptr (
                                    new WriteJob (stream, std::move (buffer))));
                        }
                        THEKOGANS_UTIL_CATCH_AND_LOG
                    }
                    else {
                        stream.WriteBuffer (std::move (buffer));
                    }
                }

                void Server::HandleSecureTCPSocketHandshakeCompleted (
                        stream::SecureTCPSocket &secureTCPSocket) throw () {
                    THEKOGANS_UTIL_LOG_INFO (
                        "Session openned (%s).\n",
                        secureTCPSocket.IsSessionReused () ? "reused" : "new");
                }

                void Server::HandleSecureTCPSocketShutdownCompleted (
                        stream::SecureTCPSocket &secureTCPSocket) throw () {
                    THEKOGANS_UTIL_LOG_INFO ("%s\n", "Session closed.");
                }

            } // namespace server
        } // namespace securetcpecho
    } // namespace stream
} // namespace thekogans
