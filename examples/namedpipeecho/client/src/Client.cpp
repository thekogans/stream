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

#include "thekogans/util/Exception.h"
#include "thekogans/util/LoggerMgr.h"
#include "thekogans/util/RandomSource.h"
#include "thekogans/util/HRTimer.h"
#include "thekogans/stream/NamedPipe.h"
#include "thekogans/stream/namedpipeecho/client/Client.h"

namespace thekogans {
    namespace stream {
        namespace namedpipeecho {
            namespace client {

                void Client::Start (const std::string &address_) {
                    address = address_;
                    ResetIo (true);
                }

                void Client::Stop () {
                    ResetIo (false);
                }

                void Client::OnTimerAlarm (util::Timer::SharedPtr /*timer*/) throw () {
                    THEKOGANS_UTIL_LOG_INFO (
                        "Start bandwidth test: %u bytes\n", sentLength);
                    util::Buffer::SharedPtr buffer (
                        new util::Buffer (util::NetworkEndian, sentLength));
                    buffer->AdvanceWriteOffset (
                        util::RandomSource::Instance ()->GetBytes (
                            buffer->GetWritePtr (),
                            buffer->GetDataAvailableForWriting ()));
                    startTime = util::HRTimer::Click ();
                    clientNamedPipe->Write (buffer);
                }

                void Client::OnStreamError (
                        Stream::SharedPtr /*stream*/,
                        util::Exception::SharedPtr exception) throw () {
                    THEKOGANS_UTIL_LOG_ERROR ("%s\n", exception->Report ().c_str ());
                }

                void Client::OnStreamDisconnect (Stream::SharedPtr stream) throw () {
                    THEKOGANS_UTIL_LOG_INFO ("%s\n", "Connection closed.");
                }

                void Client::OnStreamRead (
                        Stream::SharedPtr stream,
                        util::Buffer::SharedPtr buffer) throw () {
                    receivedLength += buffer->GetDataAvailableForReading ();
                    if (receivedLength == sentLength) {
                        endTime = util::HRTimer::Click ();
                        THEKOGANS_UTIL_LOG_INFO (
                            "End bandwidth test: %u iteration, %u bytes, %f Mb/s.\n",
                            iteration,
                            receivedLength,
                            (util::f32)((util::f64)util::HRTimer::GetFrequency () *
                                receivedLength * 8 / (endTime - startTime) / (1024 * 1024)));
                        receivedLength = 0;
                        sentLength <<= 1;
                        if (iteration++ == Options::Instance ()->iterations) {
                            sentLength = Options::Instance ()->seed;
                            iteration = 1;
                        }
                        timer->Start (util::TimeSpec::FromSeconds (1), false);
                    }
                }

                void Client::ResetIo (bool connect) {
                    util::Subscriber<stream::StreamEvents>::Unsubscribe ();
                    clientNamedPipe.Reset ();
                    if (connect) {
                        clientNamedPipe = NamedPipe::CreateClientNamedPipe (address);
                        util::Subscriber<stream::StreamEvents>::Subscribe (*clientNamedPipe);
                        clientNamedPipe->Read ();
                        THEKOGANS_UTIL_LOG_INFO ("Connected to %s.\n", address.c_str ());
                        timer->Start (util::TimeSpec::FromSeconds (1), false);
                    }
                }

            } // namespace client
        } // namespace namedpipeecho
    } // namespace stream
} // namespace thekogans

#endif // defined (TOOLCHAIN_OS_Windows)
