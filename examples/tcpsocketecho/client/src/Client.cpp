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
#include "thekogans/stream/TCPSocket.h"
#include "thekogans/stream/tcpecho/client/Options.h"
#include "thekogans/stream/tcpecho/client/Client.h"

namespace thekogans {
    namespace stream {
        namespace tcpecho {
            namespace client {

                void Client::Start () {
                    clientTCPSocket.Reset (new TCPSocket);
                    util::Subscriber<stream::StreamEvents>::Subscribe (*clientTCPSocket);
                    util::Subscriber<stream::TCPSocketEvents>::Subscribe (*clientTCPSocket);
                    clientTCPSocket->Connect (
                        stream::Address (
                            client::Options::Instance ()->port,
                            client::Options::Instance ()->address));
                }

                void Client::Stop () {
                    util::Subscriber<stream::StreamEvents>::Unsubscribe ();
                    util::Subscriber<stream::TCPSocketEvents>::Unsubscribe ();
                    clientTCPSocket.Reset ();
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
                    if (receivedLength == Options::Instance ()->blockSize) {
                        totalTime += util::HRTimer::Click () - startTime;
                        if (++iteration < Options::Instance ()->iterations) {
                            THEKOGANS_UTIL_LOG_INFO (
                                "End bandwidth test: %u bytes, %u iteration, %f Mb/s.\n",
                                Options::Instance ()->blockSize,
                                Options::Instance ()->iterations,
                                (util::f32)((util::f64)util::HRTimer::GetFrequency () *
                                    (Options::Instance ()->blockSize *
                                        Options::Instance ()->iterations) * 8 /
                                    totalTime / (1024 * 1024)));
                            util::MainRunLoop::Instance ()->Stop ();
                        }
                        else {
                            PerformTest ();
                        }
                    }
                }

                void Client::OnTCPSocketConnect (
                        TCPSocket::SharedPtr tcpSocket,
                        Address address) throw () {
                    THEKOGANS_UTIL_LOG_INFO ("Connected to %s.\n", address.ToString ().c_str ());
                    clientTCPSocket->Read (0);
                    THEKOGANS_UTIL_LOG_INFO (
                        "Start bandwidth test: %u bytes, %u iterations.\n",
                        Options::Instance ()->blockSize,
                        Options::Instance ()->iterations);
                    PerformTest ();
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
                    receivedLength = 0;
                    clientTCPSocket->Write (buffer);
                }

            } // namespace client
        } // namespace tcpecho
    } // namespace stream
} // namespace thekogans
