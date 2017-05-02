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

#include <vector>
#include "thekogans/util/OwnerList.h"
#include "thekogans/util/Exception.h"
#include "thekogans/util/LoggerMgr.h"
#include "thekogans/stream/UDPSocket.h"
#include "thekogans/stream/StreamLogger.h"
#include "thekogans/loggermgr/Server.h"

namespace thekogans {
    namespace stream {
        namespace loggermgr {

            void Server::Start (
                    const std::list<stream::Address> &addresses,
                    util::ui32 maxEntrySize,
                    util::i32 priority) {
                if (!addresses.empty ()) {
                    if (maxEntrySize > 0 && maxEntrySize <= DEFAULT_ENTRY_SIZE) {
                        if (done) {
                            eventQueue.reset (new stream::AsyncIoEventQueue ());
                            for (std::list<stream::Address>::const_iterator
                                    it = addresses.begin (),
                                    end = addresses.end (); it != end; ++it) {
                                stream::UDPSocket::Ptr udpSocket (
                                    new stream::UDPSocket (*it));
                                udpSocket->SetSendBufferSize (maxEntrySize);
                                udpSocket->SetReceiveBufferSize (maxEntrySize);
                                eventQueue->AddStream (*udpSocket, *this);
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
                            "maxEntrySize out of bounds %u (%u, %u]",
                            maxEntrySize, 0, DEFAULT_ENTRY_SIZE);
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
                    eventQueue->Break ();
                    Wait ();
                    eventQueue.reset ();
                    jobQueue.WaitForIdle ();
                }
                else {
                    THEKOGANS_UTIL_LOG_WARNING (
                        "%s\n", "Server is not running.");
                }
            }

            void Server::Run () {
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
            }

            void Server::HandleSocketReadFrom (
                    stream::Socket &socket,
                    util::Buffer::UniquePtr buffer,
                    const stream::Address &address) throw () {
                THEKOGANS_UTIL_LOG_DEBUG (
                    "Received buffer from: %s:%u\n",
                    address.AddrToString ().c_str (),
                    address.GetPort ());
                THEKOGANS_UTIL_TRY {
                    struct Job : public util::JobQueue::Job {
                        util::Buffer::UniquePtr buffer;
                        stream::Address address;

                        Job (util::Buffer::UniquePtr buffer_,
                            const stream::Address &address_) :
                            buffer (std::move (buffer_)),
                            address (address_) {}

                        // util::JobQueue::Job
                        virtual void Execute (volatile const bool &done) throw () {
                            pugi::xml_document document;
                            pugi::xml_parse_result result =
                                document.load_buffer (buffer->GetReadPtr (), buffer->GetDataAvailableForReading ());
                            if (result == pugi::status_ok) {
                                stream::StreamLogger::Entry entry (document.document_element ());
                                util::LoggerMgr::Instance ().Log (entry.subsystem.c_str (),
                                    entry.level, entry.header, entry.message);
                            }
                            else {
                                THEKOGANS_UTIL_LOG_ERROR (
                                    "Parsing error: %s, @%u",
                                    result.description (), result.offset);
                            }
                        }
                    };
                    jobQueue.Enq (
                        util::JobQueue::Job::UniquePtr (
                            new Job (std::move (buffer), address)));
                }
                THEKOGANS_UTIL_CATCH_AND_LOG
            }

        } // namespace loggermgr
    } // namespace stream
} // namespace thekogans
