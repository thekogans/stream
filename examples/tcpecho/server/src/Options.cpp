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

#include "thekogans/util/Path.h"
#include "thekogans/util/HRTimer.h"
#include "thekogans/util/ConsoleLogger.h"
#include "thekogans/util/FileLogger.h"
#include "thekogans/util/StringUtils.h"
#include "thekogans/util/XMLUtils.h"
#include "thekogans/util/File.h"
#include "thekogans/stream/tcpecho/server/Options.h"

namespace thekogans {
    namespace stream {
        namespace tcpecho {
            namespace server {

                namespace {
                    const char *OPTIONS_XML = "Options.xml";
                    const util::ui16 DEFAULT_PORT = 8854;
                }

            #if defined (_MSC_VER)
                #pragma warning (push)
                #pragma warning (disable : 4355)
            #endif // defined (_MSC_VER)

                Options::Options () :
                        help (false),
                        version (false),
                        port (DEFAULT_PORT),
                        startDirectory (util::Path::GetCurrPath ()),
                        watchId (
                            util::Directory::Watcher::Instance ().AddWatch (
                                startDirectory, *this)) {
                    if (util::Path (OPTIONS_XML).Exists ()) {
                        ReadConfig ();
                    }
                }

            #if defined (_MSC_VER)
                #pragma warning (pop)
            #endif // defined (_MSC_VER)

                void Options::DoOption (char option, const std::string &value) {
                    switch (option) {
                        case 'h':
                            help = true;
                            break;
                        case 'v':
                            version = true;
                            break;
                        case 'l':
                            loggerMgr.level =
                                util::LoggerMgr::stringTolevel (value.c_str ());
                            break;
                        case 'c':
                            loggerMgr.consoleLogger = true;
                            break;
                        case 'f':
                            loggerMgr.fileLogger.path = value;
                            break;
                        case 'r':
                            loggerMgr.fileLogger.archive = true;
                            if (!value.empty ()) {
                                loggerMgr.fileLogger.maxLogFileSize =
                                    util::stringToui32 (value.c_str ());
                            }
                            break;
                        case 'k':
                            lockFilePath = value;
                            break;
                        case 'p':
                            port = util::stringToui16 (value.c_str ());
                            break;
                        case 'a':
                            addresses.push_back (stream::Address (port, value));
                            break;
                    }
                }

                void Options::Epilog () {
                    if (addresses.empty ()) {
                        addresses.push_back (stream::Address::Any (port));
                    }
                    else if (port != DEFAULT_PORT) {
                        for (std::list<stream::Address>::iterator
                                it = addresses.begin (),
                                end = addresses.end (); it != end; ++it) {
                            (*it).SetPort (port);
                        }
                    }
                }

                void Options::HandleModified (
                        util::Directory::Watcher::WatchId watchId_,
                        const std::string &directory,
                        const util::Directory::Entry &entry) {
                    THEKOGANS_UTIL_LOG_DEBUG (
                        "watchId = %x (%x)\n"
                        "directory = %s (%s)\n"
                        "entry.name = %s (%s)\n",
                        watchId_, watchId,
                        directory.c_str (), startDirectory.c_str (),
                        entry.name.c_str (), OPTIONS_XML);
                    if (watchId_ == watchId && directory == startDirectory && entry.name == OPTIONS_XML) {
                        ReadConfig ();
                    }
                }

                void Options::ReadConfig () {
                    THEKOGANS_UTIL_TRY {
                        pugi::xml_document doc;
                        pugi::xml_parse_result result = doc.load_file (
                            util::MakePath (startDirectory, OPTIONS_XML).c_str ());
                        if (!result) {
                            // FIXME: throw
                            assert (0);
                        }
                        pugi::xml_node node = doc.document_element ();
                        if (!node.empty () && std::string (node.name ()) == "Options") {
                            for (pugi::xml_node child = node.first_child ();
                                    !child.empty (); child = child.next_sibling ()) {
                                if (child.type () == pugi::node_element) {
                                    std::string childName = child.name ();
                                    if (childName == "LoggerMgr") {
                                        ParseLoggerMgr (child);
                                    }
                                    else if (childName == "LockFile") {
                                        lockFilePath =
                                            util::Decodestring (
                                                child.attribute ("Path").value ());
                                    }
                                    else if (childName == "Listener") {
                                        ParseListener (child);
                                    }
                                }
                            }
                        }
                    }
                    THEKOGANS_UTIL_CATCH_AND_LOG
                }

                void Options::ParseLoggerMgr (const pugi::xml_node &node) {
                    loggerMgr.Reset ();
                    loggerMgr.level =
                        util::LoggerMgr::stringTolevel (node.attribute ("Level").value ());
                    loggerMgr.decorations =
                        util::LoggerMgr::stringTodecorations (
                            node.attribute ("Decorations").value ());
                    THEKOGANS_UTIL_LOG_RESET (
                        loggerMgr.level,
                        loggerMgr.decorations);
                    for (pugi::xml_node child = node.first_child ();
                            !child.empty (); child = child.next_sibling ()) {
                        if (child.type () == pugi::node_element) {
                            std::string childName = child.name ();
                            if (childName == "ConsoleLogger") {
                                loggerMgr.consoleLogger = true;
                            }
                            else if (childName == "FileLogger") {
                                loggerMgr.fileLogger.path =
                                    util::Decodestring (child.attribute ("Path").value ());
                                std::string archive = std::string (child.attribute ("Archive").value ());
                                if (!archive.empty ()) {
                                    loggerMgr.fileLogger.archive = archive == util::XML_TRUE;
                                }
                                std::string maxLogFileSize =
                                    std::string (child.attribute ("MaxLogFileSize").value ());
                                if (!maxLogFileSize.empty ()) {
                                    loggerMgr.fileLogger.maxLogFileSize =
                                        util::stringToui32 (maxLogFileSize.c_str ());
                                }
                            }
                        }
                    }
                    if (loggerMgr.consoleLogger) {
                        THEKOGANS_UTIL_LOG_ADD_LOGGER (
                            util::Logger::Ptr (new util::ConsoleLogger));
                    }
                    if (!loggerMgr.fileLogger.path.empty ()) {
                        THEKOGANS_UTIL_LOG_ADD_LOGGER (
                            util::Logger::Ptr (
                                new util::FileLogger (
                                    loggerMgr.fileLogger.path,
                                    loggerMgr.fileLogger.archive)));
                    }
                }

                void Options::ParseListener (const pugi::xml_node &node) {
                    port = util::stringToui16 (node.attribute ("Port").value ());
                    for (pugi::xml_node child = node.first_child ();
                            !child.empty (); child = child.next_sibling ()) {
                        if (child.type () == pugi::node_element &&
                            std::string (child.name ()) == "Address") {
                            std::string address = util::Decodestring (child.text ().get ());
                            if (!address.empty ()) {
                                THEKOGANS_UTIL_TRY {
                                    addresses.push_back (
                                        stream::Address (port, address));
                                }
                                THEKOGANS_UTIL_CATCH_AND_LOG
                            }
                        }
                    }
                }

            } // namespace server
        } // namespace tcpecho
    } // namespace stream
} // namespace thekogans
