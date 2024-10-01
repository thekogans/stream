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

#include "thekogans/util/Path.h"
#include "thekogans/util/HRTimer.h"
#include "thekogans/util/ConsoleLogger.h"
#include "thekogans/util/FileLogger.h"
#include "thekogans/util/XMLUtils.h"
#include "thekogans/util/File.h"
#include "thekogans/stream/namedpipeecho/server/Options.h"

namespace thekogans {
    namespace stream {
        namespace namedpipeecho {
            namespace server {

                namespace {
                    const char * const OPTIONS_XML = "Options.xml";

                    const char * const TAG_OPTIONS = "Options";
                    const char * const TAG_LOGGER_MGR = "LoggerMgr";
                    const char * const ATTR_LEVEL = "Level";
                    const char * const ATTR_DECORATIONS = "Decorations";
                    const char * const TAG_CONSOLE_LOGGER = "ConsoleLogger";
                    const char * const TAG_FILE_LOGGER = "FileLogger";
                    const char * const ATTR_PATH = "Path";
                    const char * const ATTR_ARCHIVE = "Archive";
                    const char * const ATTR_MAX_LOG_FILE_SIZE = "MaxLogFileSize";
                    const char * const TAG_LOCK_FILE = "LockFile";
                    const char * const TAG_LISTENER = "Listener";
                    const char * const ATTR_ADDRESS = "Address";
                }

            #if defined (_MSC_VER)
                #pragma warning (push)
                #pragma warning (disable : 4355)
            #endif // defined (_MSC_VER)

                Options::Options () :
                        help (false),
                        version (false),
                        startDirectory (util::Path::GetCurrDirectory ()),
                        watchId (
                            util::Directory::Watcher::Instance ()->AddWatch (
                                startDirectory, *this)) {
                    if (util::Path (OPTIONS_XML).Exists ()) {
                        ReadConfig ();
                    }
                }

            #if defined (_MSC_VER)
                #pragma warning (pop)
            #endif // defined (_MSC_VER)

                void Options::DoOption (
                        char option,
                        const std::string &value) {
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
                        case 'r': {
                            loggerMgr.fileLogger.archive = true;
                            if (!value.empty ()) {
                                loggerMgr.fileLogger.maxLogFileSize =
                                    util::stringToui32 (value.c_str ());
                            }
                            break;
                        }
                        case 'k':
                            lockFilePath = value;
                            break;
                        case 'a':
                            address = value;
                            break;
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
                    if (watchId_ == watchId &&
                            directory == startDirectory &&
                            entry.name == OPTIONS_XML) {
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
                        if (!node.empty () && std::string (node.name ()) == TAG_OPTIONS) {
                            for (pugi::xml_node child = node.first_child ();
                                    !child.empty (); child = child.next_sibling ()) {
                                if (child.type () == pugi::node_element) {
                                    std::string childName = child.name ();
                                    if (childName == TAG_LOGGER_MGR) {
                                        ParseLoggerMgr (child);
                                    }
                                    else if (childName == TAG_LOCK_FILE) {
                                        lockFilePath =
                                            util::Decodestring (
                                                child.attribute (ATTR_PATH).value ());
                                    }
                                    else if (childName == TAG_LISTENER) {
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
                        util::LoggerMgr::stringTolevel (node.attribute (ATTR_LEVEL).value ());
                    loggerMgr.decorations =
                        util::LoggerMgr::stringTodecorations (
                            node.attribute (ATTR_DECORATIONS).value ());
                    THEKOGANS_UTIL_LOG_RESET (loggerMgr.level, loggerMgr.decorations);
                    for (pugi::xml_node child = node.first_child ();
                            !child.empty (); child = child.next_sibling ()) {
                        if (child.type () == pugi::node_element) {
                            std::string childName = child.name ();
                            if (childName == TAG_CONSOLE_LOGGER) {
                                loggerMgr.consoleLogger = true;
                            }
                            else if (childName == TAG_FILE_LOGGER) {
                                loggerMgr.fileLogger.path =
                                    util::Decodestring (child.attribute (ATTR_PATH).value ());
                                std::string archive = std::string (
                                    child.attribute (ATTR_ARCHIVE).value ());
                                if (!archive.empty ()) {
                                    loggerMgr.fileLogger.archive = archive == util::XML_TRUE;
                                }
                                std::string maxLogFileSize =
                                    std::string (child.attribute (ATTR_MAX_LOG_FILE_SIZE).value ());
                                if (!maxLogFileSize.empty ()) {
                                    loggerMgr.fileLogger.maxLogFileSize =
                                        util::stringToui32 (maxLogFileSize.c_str ());
                                }
                            }
                        }
                    }
                    if (loggerMgr.consoleLogger) {
                        THEKOGANS_UTIL_LOG_ADD_LOGGER (
                            util::Logger::SharedPtr (new util::ConsoleLogger));
                    }
                    if (!loggerMgr.fileLogger.path.empty ()) {
                        THEKOGANS_UTIL_LOG_ADD_LOGGER (
                            util::Logger::SharedPtr (
                                new util::FileLogger (
                                    loggerMgr.fileLogger.path,
                                    loggerMgr.fileLogger.archive)));
                    }
                }

                void Options::ParseListener (const pugi::xml_node &node) {
                    for (pugi::xml_node child = node.first_child ();
                            !child.empty (); child = child.next_sibling ()) {
                        if (child.type () == pugi::node_element &&
                                std::string (child.name ()) == ATTR_ADDRESS) {
                            address = util::Decodestring (child.text ().get ());
                        }
                    }
                }

            } // namespace server
        } // namespace namedpipeecho
    } // namespace stream
} // namespace thekogans

#endif // defined (TOOLCHAIN_OS_Windows)
