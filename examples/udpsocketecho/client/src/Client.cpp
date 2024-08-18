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
#include "thekogans/util/RandomSource.h"
#include "thekogans/util/HRTimer.h"
#include "thekogans/util/MainRunLoop.h"
#include "thekogans/stream/UDPSocket.h"
#include "thekogans/stream/udpecho/client/Options.h"
#include "thekogans/stream/udpecho/client/Client.h"

namespace thekogans {
    namespace stream {
        namespace udpecho {
            namespace client {

                void Client::Start () {
                    clientUDPSocket.Reset (new UDPSocket);
                    util::Subscriber<stream::StreamEvents>::Subscribe (*clientUDPSocket);
                    util::Subscriber<stream::UDPSocketEvents>::Subscribe (*clientUDPSocket);
                    clientUDPSocket->SetSendBufferSize (Options::Instance ()->blockSize);
                    clientUDPSocket->SetReceiveBufferSize (Options::Instance ()->blockSize);
                    clientUDPSocket->Bind (Address::Any (0));
                    if (Options::Instance ()->message) {
                        clientUDPSocket->SetRecvPktInfo (true);
                        clientUDPSocket->ReadMsg (Options::Instance ()->blockSize);
                    }
                    else {
                        clientUDPSocket->ReadFrom (Options::Instance ()->blockSize);
                    }
                    THEKOGANS_UTIL_LOG_INFO (
                        "Start bandwidth test: %u bytes, %u iterations\n",
                        Options::Instance ()->blockSize,
                        Options::Instance ()->iterations);
                    PerformTest ();
                }

                void Client::Stop () {
                    util::Subscriber<stream::StreamEvents>::Unsubscribe ();
                    util::Subscriber<stream::UDPSocketEvents>::Unsubscribe ();
                    clientUDPSocket.Reset ();
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
                    startTime = util::HRTimer::Click ();
                    clientUDPSocket->WriteTo (
                        buffer,
                        Address (
                            Options::Instance ()->port,
                            Options::Instance ()->address));
                }

                void Client::OnStreamError (
                        Stream::SharedPtr /*stream*/,
                        util::Exception::SharedPtr exception) throw () {
                    THEKOGANS_UTIL_LOG_ERROR ("%s\n", exception->Report ().c_str ());
                }

                void Client::OnUDPSocketReadFrom (
                        UDPSocket::SharedPtr udpSocket,
                        util::Buffer::SharedPtr buffer,
                        Address address) throw () {
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

                void Client::OnUDPSocketReadMsg (
                        UDPSocket::SharedPtr udpSocket,
                        util::Buffer::SharedPtr buffer,
                        Address from,
                        Address to) throw () {
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

            } // namespace client
        } // namespace udpecho
    } // namespace stream
} // namespace thekogans
