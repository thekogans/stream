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
#include "thekogans/util/Exception.h"
#include "thekogans/util/LoggerMgr.h"
#include "thekogans/util/ConsoleLogger.h"
#include "thekogans/util/Version.h"
#include "thekogans/stream/Address.h"
#include "thekogans/stream/UDPSocket.h"
#include "thekogans/stream/Version.h"
#include "thekogans/stream/udpecho/client/Options.h"
#include "thekogans/stream/udpecho/client/Version.h"

using namespace thekogans;
using namespace thekogans::stream::udpecho;

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

    const util::ui32 DEFAULT_MAX_PACKET_SIZE = 64 * 1024;

    util::f32 GetBandwidth (
            const stream::Address &address,
            util::ui32 maxPacketSize = DEFAULT_MAX_PACKET_SIZE,
            util::ui32 rounds = 10,
            util::ui32 seed = 64,
            util::f32 a = 2.0f,
            util::f32 b = 0.0f,
            const util::TimeSpec &timeSpec =
                util::TimeSpec::FromSeconds (3)) {
        util::ui32 bytes = 0;
        util::ui64 time = 0;
        stream::UDPSocket socket (
            stream::Address::Any (0, address.GetFamily ()));
        socket.SetSendBufferSize (maxPacketSize);
        socket.SetReceiveBufferSize (maxPacketSize);
        if (timeSpec != util::TimeSpec::Zero) {
            socket.SetReadTimeout (timeSpec);
            socket.SetWriteTimeout (timeSpec);
        }
        stream::Address peerAddress;
        for (util::ui32 i = 0; i < rounds; ++i) {
            THEKOGANS_UTIL_TRY {
                std::vector<util::ui8> buffer (seed);
                util::ui64 start = util::HRTimer::Click ();
                bytes +=
                    socket.WriteTo (&buffer[0], seed, address) +
                    socket.ReadFrom (&buffer[0], seed, peerAddress);
                time += util::HRTimer::Click () - start;
            }
            THEKOGANS_UTIL_CATCH_AND_LOG
            seed = (util::ui32)(a * seed + b);
        }
        return time > 0 ? (util::f32)
            ((util::f64)util::HRTimer::GetFrequency () *
                bytes * 8 / time / (1024 * 1024)) : 0.0f;
    }
}

int main (
        int argc,
        const char *argv[]) {
    client::Options::Instance ().Parse (argc, argv, "hvlapt");
    THEKOGANS_UTIL_LOG_INIT (
        client::Options::Instance ().logLevel,
        util::LoggerMgr::All);
    THEKOGANS_UTIL_LOG_ADD_LOGGER (
        util::Logger::Ptr (new util::ConsoleLogger));
    if (client::Options::Instance ().help) {
        THEKOGANS_UTIL_LOG_INFO (
            "%s [-h] [-v] [-l:'%s'] -a:'host address' [-p:'host port'] [-t:seconds]\n\n"
            "h - Display this help message.\n"
            "v - Display version information.\n"
            "l - Set logging level.\n"
            "a - Address the server is listening on.\n"
            "p - Port the server is listening on (default is 8854).\n"
            "t - Socket send/receive timeout (default is 3 seconds).\n",
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
            util::f32 bandwidth = GetBandwidth (
                stream::Address (
                    client::Options::Instance ().port,
                    client::Options::Instance ().addr),
                DEFAULT_MAX_PACKET_SIZE, 10, 64, 2.0f, 0.0f,
                util::TimeSpec::FromSeconds (client::Options::Instance ().timeout));
            THEKOGANS_UTIL_LOG_INFO ("Bandwidth: %f Mb/s.\n", bandwidth);
        }
        THEKOGANS_UTIL_CATCH_AND_LOG
    }
    THEKOGANS_UTIL_LOG_FLUSH
    return 0;
}
