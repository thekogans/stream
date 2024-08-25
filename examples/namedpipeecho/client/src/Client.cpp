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
#include "thekogans/util/RandomSource.h"
#include "thekogans/util/HRTimer.h"
#include "thekogans/util/RunLoopScheduler.h"
#include "thekogans/util/MainRunLoop.h"
#include "thekogans/stream/NamedPipe.h"
#include "thekogans/stream/namedpipeecho/client/Options.h"
#include "thekogans/stream/namedpipeecho/client/Client.h"

namespace thekogans {
    namespace stream {
        namespace namedpipeecho {
            namespace client {

                void Client::Start () {
                    if (NamedPipe::Wait (Options::Instance ()->address, 0)) {
                        THEKOGANS_UTIL_LOG_INFO (
                            "Connecting to %s.\n",
                            Options::Instance ()->address.c_str ());
                        clientNamedPipe = NamedPipe::CreateClientNamedPipe (
                            Options::Instance ()->address);
                        util::Subscriber<stream::StreamEvents>::Subscribe (*clientNamedPipe);
                        clientNamedPipe->Read ();
                        THEKOGANS_UTIL_LOG_INFO (
                            "Start bandwidth test: %u bytes, %u iterations\n",
                            Options::Instance ()->blockSize,
                            Options::Instance ()->iterations);
                        PerformTest ();
                    }
                    else {
                        THEKOGANS_UTIL_LOG_WARNING (
                            "%s is unavailable. Sleeping %u seconds to retry.\n",
                            Options::Instance ()->address.c_str (),
                            Options::Instance ()->timeout);
                        util::GlobalRunLoopScheduler::Instance ()->ScheduleRunLoopJob (
                            [] (const util::RunLoop::LambdaJob & /*job*/,
                                    const std::atomic<bool> &done) {
                                if (!done) {
                                    Client::Instance ()->Start ();
                                }
                            },
                            util::TimeSpec::FromSeconds (Options::Instance ()->timeout));
                    }
                }

                void Client::Stop () {
                    util::Subscriber<stream::StreamEvents>::Unsubscribe ();
                    clientNamedPipe.Reset ();
                }

                void Client::PerformTest () {
                    util::Buffer::SharedPtr buffer (
                        new util::Buffer (
                            util::NetworkEndian,
                            Options::Instance ()->blockSize));
                    buffer->AdvanceWriteOffset (
                        util::RandomSource::Instance ()->GetBytes (
                            buffer->GetWritePtr (),
                            buffer->GetDataAvailableForWriting ()));
                    receivedLength = 0;
                    startTime = util::HRTimer::Click ();
                    clientNamedPipe->Write (buffer);
                }

                void Client::OnStreamError (
                        Stream::SharedPtr /*stream*/,
                        const util::Exception &exception) throw () {
                    THEKOGANS_UTIL_LOG_ERROR ("%s\n", exception.Report ().c_str ());
                }

                void Client::OnStreamDisconnect (Stream::SharedPtr stream) throw () {
                    THEKOGANS_UTIL_LOG_INFO ("%s\n", "Connection closed.");
                }

                void Client::OnStreamRead (
                        Stream::SharedPtr stream,
                        util::Buffer::SharedPtr buffer) throw () {
                    receivedLength += buffer->GetDataAvailableForReading ();
                    if (receivedLength == Options::Instance ()->blockSize) {
                        totalTime += util::HRTimer::Click () - startTime;
                        if (++iteration < Options::Instance ()->iterations) {
                            PerformTest ();
                        }
                        else {
                            THEKOGANS_UTIL_LOG_INFO (
                                "End bandwidth test: %u bytes, %u iterations, %f Mb/s.\n",
                                Options::Instance ()->blockSize,
                                Options::Instance ()->iterations,
                                (util::f32)((util::f64)util::HRTimer::GetFrequency () *
                                    (Options::Instance ()->blockSize *
                                        Options::Instance ()->iterations) * 8 /
                                    totalTime / (1024 * 1024)));
                            util::MainRunLoop::Instance ()->Stop ();
                        }
                    }
                }

            } // namespace client
        } // namespace namedpipeecho
    } // namespace stream
} // namespace thekogans

#endif // defined (TOOLCHAIN_OS_Windows)
