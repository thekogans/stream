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
                    if (!buffer->IsEmpty ()) {
                        util::GlobalJobQueue::Instance ()->EnqJob (
                            [stream, buffer] (
                                    const util::RunLoop::LambdaJob & /*job*/,
                                    const std::atomic<bool> & /*done*/) {
                                stream->Write (buffer);
                            }
                        );
                    }
                }

                /*
    util::f32 GetBandwidth (
            const stream::Address &address,
            util::ui32 rounds = 10,
            util::ui32 seed = 64,
            util::f32 a = 2.0f,
            util::f32 b = 0.0f) {
        util::ui32 bytes = 0;
        util::ui64 time = 0;
        for (util::ui32 i = 0; i < rounds; ++i) {
            THEKOGANS_UTIL_TRY {
                util::ui64 start = util::HRTimer::Click ();
                {
                    stream::ClientNamedPipe namedPipe (address);
                    std::vector<util::ui8> buffer (seed);
                    namedPipe.WriteFullBuffer (&buffer[0], seed);
                    namedPipe.ReadFullBuffer (&buffer[0], seed);
                }
                time += util::HRTimer::Click () - start;
                bytes += seed + seed;
            }
            THEKOGANS_UTIL_CATCH_AND_LOG
            seed = (util::ui32)(a * seed + b);
        }
        return time > 0 ? (util::f32)
            ((util::f64)util::HRTimer::GetFrequency () *
                bytes * 8 / time / (1024 * 1024)) : 0.0f;
    }
            THEKOGANS_UTIL_LOG_INFO (
                "Conducting a bandwidth test with: %s\n",
                client::Options::Instance ()->address.c_str ());
            util::f32 bandwidth = GetBandwidth (
                stream::Address (client::Options::Instance ()->address));
            THEKOGANS_UTIL_LOG_INFO ("Bandwidth: %f Mb/s.\n", bandwidth);
                */

                void Client::ResetIo (bool connect) {
                    util::Subscriber<stream::StreamEvents>::Unsubscribe ();
                    clientNamedPipe.Reset ();
                    if (connect) {
                        clientNamedPipe = NamedPipe::CreateClientNamedPipe (address);
                        util::Subscriber<stream::StreamEvents>::Subscribe (*clientNamedPipe);
                        clientNamedPipe->Read ();

                    }
                }

            } // namespace client
        } // namespace namedpipeecho
    } // namespace stream
} // namespace thekogans

#endif // defined (TOOLCHAIN_OS_Windows)
