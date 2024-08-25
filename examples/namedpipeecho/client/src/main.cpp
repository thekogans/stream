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

#include <vector>
#include <list>
#include <string>
#include "thekogans/util/Types.h"
#include "thekogans/util/TimeSpec.h"
#include "thekogans/util/Exception.h"
#include "thekogans/util/LoggerMgr.h"
#include "thekogans/util/ConsoleLogger.h"
#include "thekogans/util/MainRunLoop.h"
#include "thekogans/util/Version.h"
#include "thekogans/stream/Address.h"
#include "thekogans/stream/Version.h"
#include "thekogans/stream/namedpipeecho/client/Options.h"
#include "thekogans/stream/namedpipeecho/client/Version.h"
#include "thekogans/stream/namedpipeecho/client/Client.h"

using namespace thekogans;
using namespace thekogans::stream::namedpipeecho;

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
    client::Options::Instance ()->Parse (argc, argv, "hvlabi");
    THEKOGANS_UTIL_LOG_INIT (
        client::Options::Instance ()->logLevel,
        util::LoggerMgr::All);
    THEKOGANS_UTIL_LOG_ADD_LOGGER (new util::ConsoleLogger);
    THEKOGANS_UTIL_IMPLEMENT_LOG_FLUSHER;
    if (client::Options::Instance ()->help) {
        THEKOGANS_UTIL_LOG_INFO (
            "%s [-h] [-v] [-l:'%s'] -a:'host address' "
            "[-b:'block size'] [-i:'iterations'] [-t:'timeout']\n\n"
            "h - Display this help message.\n"
            "v - Display version information.\n"
            "l - Set logging level.\n"
            "a - Address server is listening on.\n"
            "b - Block size in 1K chuncks (default is 63).\n"
            "i - Iterations (default is 16).\n"
            "t - Timeout in seconds (default is 1).\n",
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
    else if (client::Options::Instance ()->address.empty ()) {
        THEKOGANS_UTIL_LOG_ERROR ("%s\n", "Empty address.");
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

#else // defined (TOOLCHAIN_OS_Windows)

#include <iostream>

int main (
        int /*argc*/,
        const char * /*argv*/[]) {
    std::cerr << "namedpipeecho client runs only on Windows." << std::endl;
    return 0;
}

#endif // defined (TOOLCHAIN_OS_Windows)
