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

#if !defined (__thekogans_stream_tcpecho_server_Options_h)
#define __thekogans_stream_tcpecho_server_Options_h

#include <string>
#include <list>
#include <pugixml/pugixml.hpp>
#include "thekogans/util/Types.h"
#include "thekogans/util/Singleton.h"
#include "thekogans/util/CommandLineOptions.h"
#include "thekogans/util/Directory.h"
#include "thekogans/util/LoggerMgr.h"
#include "thekogans/util/FileLogger.h"
#include "thekogans/stream/Address.h"

namespace thekogans {
    namespace stream {
        namespace tcpecho {
            namespace server {

                struct Options :
                        public util::Singleton<Options>,
                        public util::CommandLineOptions,
                        public util::Directory::Watcher::EventSink {
                    bool help;
                    bool version;
                    struct LoggerMgr {
                        util::ui32 level;
                        util::ui32 decorations;
                        bool consoleLogger;
                        struct FileLogger {
                            std::string path;
                            bool archive;
                            util::ui32 maxLogFileSize;

                            FileLogger () :
                                archive (true),
                                maxLogFileSize (util::FileLogger::DEFAULT_MAX_LOG_FILE_SIZE) {}

                            void Reset () {
                                path.clear ();
                                archive = true;
                                maxLogFileSize = util::FileLogger::DEFAULT_MAX_LOG_FILE_SIZE;
                            }
                        } fileLogger;

                        LoggerMgr () :
                            level (util::LoggerMgr::Info),
                            decorations (util::LoggerMgr::All),
                            consoleLogger (false) {}

                        void Reset () {
                            level = util::LoggerMgr::Info;
                            decorations = util::LoggerMgr::All;
                            consoleLogger = false;
                            fileLogger.Reset ();
                        }
                    } loggerMgr;
                    std::string lockFilePath;
                    util::ui16 port;
                    std::list<Address> addresses;
                    std::string startDirectory;
                    util::Directory::Watcher::WatchId watchId;

                    Options ();

                    // util::CommandLineOptions
                    virtual void DoOption (
                        char option,
                        const std::string &value);
                    virtual void Epilog ();

                    // util::Directory::Watcher::EventSink
                    virtual void HandleModified (
                        util::Directory::Watcher::WatchId watchId_,
                        const std::string &directory,
                        const util::Directory::Entry &entry);

                private:
                    void ReadConfig ();
                    void ParseLoggerMgr (const pugi::xml_node &node);
                    void ParseListener (const pugi::xml_node &node);
                };

            } // namespace server
        } // namespace tcpecho
    } // namespace stream
} // namespace thekogans

#endif // !defined (__thekogans_stream_tcpecho_server_Options_h)
