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
#include <list>
#include <string>
#include "thekogans/util/Types.h"
#include "thekogans/util/HRTimer.h"
#include "thekogans/util/TimeSpec.h"
#include "thekogans/util/MainRunLoop.h"
#include "thekogans/util/Exception.h"
#include "thekogans/util/LoggerMgr.h"
#include "thekogans/util/ConsoleLogger.h"
#include "thekogans/util/Version.h"
#include "thekogans/stream/AsyncIoEventSink.h"
#include "thekogans/stream/AsyncIoEventQueue.h"
#include "thekogans/stream/Address.h"
#include "thekogans/stream/TCPSocket.h"
#include "thekogans/stream/Version.h"
#include "thekogans/stream/tcpecho/client/Options.h"
#include "thekogans/stream/tcpecho/client/Version.h"

using namespace thekogans;
using namespace thekogans::stream::tcpecho;

namespace {
    std::string GetLogLevelList (const std::string &separator) {
        std::string logLevelList;
        {
            std::list<util::ui32> levels;
            util::LoggerMgr::GetLogLevels (levels);
            if (!levels.empty ()) {
                std::list<util::ui32>::const_iterator it = levels.begin ();
                logLevelList = util::LoggerMgr::levelTostring (*it++);
                for (std::list<util::ui32>::const_iterator end = levels.end (); it != end; ++it) {
                    logLevelList += separator + util::LoggerMgr::levelTostring (*it);
                }
            }
            else {
                logLevelList = "No LoggerMgr levels defined";
            }
        }
        return logLevelList;
    }

    struct BandwidthTester : public stream::AsyncIoEventSink {
    private:
        util::ui32 rounds;
        util::ui32 seed;
        util::f32 a;
        util::f32 b;
        util::TimeSpec timeSpec;
        util::ui64 start;
        util::ui32 round;
        std::size_t roundBytes;
        std::size_t receivedBytes;
        std::size_t totalBytes;
        util::f32 bandwidth;

    public:
        BandwidthTester (
                util::ui32 rounds_ = 10,
                util::ui32 seed_ = 64,
                util::f32 a_ = 2.0f,
                util::f32 b_ = 0.0f,
                const util::TimeSpec &timeSpec_ = util::TimeSpec::FromSeconds (3)) :
                rounds (rounds_),
                seed (seed_),
                a (a_),
                b (b_),
                timeSpec (timeSpec_),
                start (0),
                round (0),
                roundBytes (0),
                receivedBytes (0),
                totalBytes (0),
                bandwidth (0.0f) {
            stream::GlobalAsyncIoEventQueue::Instance ().SetTimeoutPolicy (
                stream::AsyncIoEventQueue::TimeoutPolicy::UniquePtr (
                    new stream::AsyncIoEventQueue::DefaultTimeoutPolicy (
                        stream::GlobalAsyncIoEventQueue::Instance ())));
        }

        void TestBandwidth (const stream::Address &address) {
            stream::TCPSocket::Ptr tcpSocket (
                new stream::TCPSocket (address.GetFamily (), SOCK_STREAM, IPPROTO_TCP));
            //if (timeSpec != util::TimeSpec::Zero) {
            //    tcpSocket->SetReadTimeout (timeSpec);
            //    tcpSocket->SetWriteTimeout (timeSpec);
            //}
            stream::GlobalAsyncIoEventQueue::Instance ().AddStream (*tcpSocket, *this);
            tcpSocket->Connect (address);
        }

        util::f32 GetBandwidth () const {
            return bandwidth;
        }

    private:
        // util::RefCounted
        virtual void Harakiri () {}

        // stream::AsyncIoEventSink
        virtual void HandleStreamError (
                stream::Stream &stream,
                const util::Exception &exception) throw () {
            THEKOGANS_UTIL_LOG_ERROR ("%s\n", exception.Report ().c_str ());
            stream::GlobalAsyncIoEventQueue::Instance ().DeleteStream (stream);
            util::MainRunLoop::Instance ().Stop ();
        }

        virtual void HandleTCPSocketConnected (stream::TCPSocket &tcpSocket) throw () {
            start = util::HRTimer::Click ();
            round = 0;
            roundBytes = seed;
            receivedBytes = 0;
            totalBytes = 0;
            bandwidth = 0.0f;
            tcpSocket.WriteBuffer (util::Buffer (util::HostEndian, roundBytes, 0, roundBytes));
        }

        virtual void HandleStreamDisconnect (stream::Stream &stream) throw () {
            stream::GlobalAsyncIoEventQueue::Instance ().DeleteStream (stream);
            util::MainRunLoop::Instance ().Stop ();
        }

        virtual void HandleStreamRead (
                stream::Stream &stream,
                util::Buffer buffer) throw () {
            receivedBytes += buffer.GetDataAvailableForReading ();
            totalBytes += buffer.GetDataAvailableForReading ();
            if (receivedBytes == roundBytes) {
                if (++round < rounds) {
                    roundBytes = (std::size_t)(a * roundBytes + b);
                    receivedBytes = 0;
                    stream.WriteBuffer (util::Buffer (util::HostEndian, roundBytes, 0, roundBytes));
                }
                else {
                    util::ui64 time = util::HRTimer::Click () - start;
                    bandwidth = (util::f32)((util::f64)util::HRTimer::GetFrequency () *
                        totalBytes * 8 / time / (1024 * 1024));
                    ((stream::TCPSocket *)&stream)->Shutdown ();
                }
            }
        }

        virtual void HandleStreamWrite (
                stream::Stream &stream,
                util::Buffer buffer) throw () {
            totalBytes += buffer.GetDataConsumed ();
        }
    };

    util::f32 TestBandwidth (
            const stream::Address &address,
            util::ui32 rounds = 10,
            util::ui32 seed = 64,
            util::f32 a = 2.0f,
            util::f32 b = 0.0f,
            const util::TimeSpec &timeSpec = util::TimeSpec::FromSeconds (3)) {
        stream::TCPSocket socket (address.GetFamily (), SOCK_STREAM, IPPROTO_TCP);
        if (timeSpec != util::TimeSpec::Zero) {
            socket.SetReadTimeout (timeSpec);
            socket.SetWriteTimeout (timeSpec);
        }
        socket.Connect (address);
        util::ui32 bytes = 0;
        util::ui64 start = util::HRTimer::Click ();
        for (util::ui32 i = 0; i < rounds; ++i) {
            THEKOGANS_UTIL_TRY {
                {
                    util::Buffer buffer (util::HostEndian, seed, 0, seed);
                    socket.WriteFullBuffer (buffer.GetReadPtr (), buffer.GetDataAvailableForReading ());
                }
                {
                    util::Buffer buffer (util::HostEndian, seed);
                    socket.ReadFullBuffer (buffer.GetWritePtr (), buffer.GetDataAvailableForWriting ());
                }
                bytes += seed + seed;
            }
            THEKOGANS_UTIL_CATCH_AND_LOG
            seed = (util::ui32)(a * seed + b);
        }
        util::ui64 time = util::HRTimer::Click () - start;
        return (util::f32)((util::f64)util::HRTimer::GetFrequency () *
            bytes * 8 / time / (1024 * 1024));
    }
}

int main (
        int argc,
        const char *argv[]) {
    client::Options::Instance ().Parse (argc, argv, "hvlaprsfcty");
    THEKOGANS_UTIL_LOG_RESET (
        client::Options::Instance ().logLevel,
        util::LoggerMgr::All);
    THEKOGANS_UTIL_LOG_ADD_LOGGER (util::Logger::Ptr (new util::ConsoleLogger));
    THEKOGANS_UTIL_IMPLEMENT_LOG_FLUSHER;
    if (client::Options::Instance ().help) {
        THEKOGANS_UTIL_LOG_INFO (
            "%s [-h] [-v] [-l:'%s'] -a:'host address' [-p:'host port'] "
            "[-r:rounds] [-s:seed] [-f:factor] [-c:constant] [-t:seconds] [-y]\n\n"
            "h - Display this help message.\n"
            "v - Display version information.\n"
            "l - Set logging level (default is Info).\n"
            "a - Address server is listening on (default is 127.0.0.1).\n"
            "p - Port server is listening on (default is 8854).\n"
            "r - Number of rounds (default is 10).\n"
            "s - Initial packet size (default is 64).\n"
            "f - Multiplicative factor (default is 2.0f).\n"
            "c - Additive constant (default is 0.0f).\n"
            "t - Socket send/receive timeout (default is 3 seconds).\n"
            "y - Async client (default is sync).\n",
            argv[0],
            GetLogLevelList (" | ").c_str ());
    }
    else if (client::Options::Instance ().version) {
        THEKOGANS_UTIL_LOG_INFO (
            "libthekogans_util - %s\n"
            "libthekogans_stream - %s\n"
            "%s - %s\n",
            util::GetVersion ().ToString ().c_str (),
            stream::GetVersion ().ToString ().c_str (),
            argv[0], client::GetVersion ().ToString ().c_str ());
    }
    else if (client::Options::Instance ().addr.empty ()) {
        THEKOGANS_UTIL_LOG_ERROR ("%s\n", "Empty address.");
    }
    else {
        THEKOGANS_UTIL_TRY {
            THEKOGANS_UTIL_LOG_INFO (
                "Conducting a bandwidth test with: %s:%u\n",
                client::Options::Instance ().addr.c_str (),
                client::Options::Instance ().port);
            if (client::Options::Instance ().async) {
                BandwidthTester bandwidthTester (
                    client::Options::Instance ().rounds,
                    client::Options::Instance ().seed,
                    client::Options::Instance ().a,
                    client::Options::Instance ().b,
                    util::TimeSpec::FromSeconds (client::Options::Instance ().timeout));
                bandwidthTester.TestBandwidth (
                    stream::Address (
                        client::Options::Instance ().port,
                        client::Options::Instance ().addr));
                util::MainRunLoop::Instance ().Start ();
                THEKOGANS_UTIL_LOG_INFO ("Bandwidth: %f Mb/s.\n", bandwidthTester.GetBandwidth ());
            }
            else {
                util::f32 bandwidth = TestBandwidth (
                    stream::Address (
                        client::Options::Instance ().port,
                        client::Options::Instance ().addr),
                    client::Options::Instance ().rounds,
                    client::Options::Instance ().seed,
                    client::Options::Instance ().a,
                    client::Options::Instance ().b,
                    util::TimeSpec::FromSeconds (client::Options::Instance ().timeout));
                THEKOGANS_UTIL_LOG_INFO ("Bandwidth: %f Mb/s.\n", bandwidth);
            }
        }
        THEKOGANS_UTIL_CATCH_AND_LOG
    }
    return 0;
}
