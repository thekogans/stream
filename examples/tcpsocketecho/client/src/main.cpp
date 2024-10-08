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

#include <list>
#include <string>
#include "thekogans/util/Types.h"
#include "thekogans/util/MainRunLoop.h"
#include "thekogans/util/Exception.h"
#include "thekogans/util/LoggerMgr.h"
#include "thekogans/util/ConsoleLogger.h"
#include "thekogans/util/Version.h"
#include "thekogans/stream/Address.h"
#include "thekogans/stream/TCPSocket.h"
#include "thekogans/stream/Version.h"
#include "thekogans/stream/tcpecho/client/Options.h"
#include "thekogans/stream/tcpecho/client/Version.h"
#include "thekogans/stream/tcpecho/client/Client.h"

using namespace thekogans;
using namespace thekogans::stream::tcpecho;

namespace {
    std::string GetLevelsList (const std::string &separator) {
        std::string logLevelList;
        {
            std::list<util::ui32> levels;
            util::LoggerMgr::GetLevels (levels);
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
}

int main (
        int argc,
        const char *argv[]) {
    client::Options::Instance ()->Parse (argc, argv, "hvlaprsfcty");
    THEKOGANS_UTIL_LOG_RESET (
        client::Options::Instance ()->logLevel,
        util::LoggerMgr::All);
    THEKOGANS_UTIL_LOG_ADD_LOGGER (new util::ConsoleLogger);
    THEKOGANS_UTIL_IMPLEMENT_LOG_FLUSHER;
    if (client::Options::Instance ()->help) {
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
            GetLevelsList (" | ").c_str ());
    }
    else if (client::Options::Instance ()->version) {
        THEKOGANS_UTIL_LOG_INFO (
            "libthekogans_util - %s\n"
            "libthekogans_stream - %s\n"
            "%s - %s\n",
            util::GetVersion ().ToString ().c_str (),
            stream::GetVersion ().ToString ().c_str (),
            argv[0], client::GetVersion ().ToString ().c_str ());
    }
    else {
        THEKOGANS_UTIL_TRY {
            THEKOGANS_UTIL_LOG_INFO ("%s starting.\n", argv[0]);
            client::Client::Instance ()->Start ();
            util::MainRunLoop::Instance ()->Start ();
            client::Client::Instance ()->Stop ();
            THEKOGANS_UTIL_LOG_INFO ("%s exiting.\n", argv[0]);
        }
        THEKOGANS_UTIL_CATCH_AND_LOG
    }
    return 0;
}
