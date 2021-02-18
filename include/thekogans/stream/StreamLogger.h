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

#if !defined (__thekogans_stream_StreamLogger_h)
#define __thekogans_stream_StreamLogger_h

#include <string>
#include "pugixml/pugixml.hpp"
#include "thekogans/util/Logger.h"
#include "thekogans/stream/Config.h"
#include "thekogans/stream/Stream.h"

namespace thekogans {
    namespace stream {

        /// \struct StreamLogger StreamLogger.h thekogans/stream/StreamLogger.h
        ///
        /// \brief
        /// A pluggable \see{thekogans::util::Logger} instance used to write log entries to a
        /// stream. Use this Logger to create a networked LoggerMgr (see examples/loggermgr)
        /// which collects log entries from remote hosts in a centralized place. StreamLogger
        /// is completely stream agnostic. All it does is package the log entries as XML,
        /// and call stream->Write. An ideal stream for StreamLogger is async UDPSocket.
        /// But realistically, you can use anything you want (as long as the loggermgr
        /// is listening).

        struct _LIB_THEKOGANS_STREAM_DECL StreamLogger : public util::Logger {
            /// \struct StreamLogger::Entry StreamLogger.h thekogans/stream/StreamLogger.h
            ///
            /// \brief
            /// Represents a serialized LoggerMgr entry.
            struct _LIB_THEKOGANS_STREAM_DECL Entry : public util::RefCounted {
                /// \brief
                /// Declare \see{RefCounted} pointers.
                THEKOGANS_UTIL_DECLARE_REF_COUNTED_POINTERS (Entry)

                /// \brief
                /// "Entry"
                static const char * const TAG_ENTRY;
                /// \brief
                /// "Subsystem"
                static const char * const ATTR_SUBSYSTEM;
                /// \brief
                /// "Level"
                static const char * const ATTR_LEVEL;
                /// \brief
                /// "Header"
                static const char * const TAG_HEADER;
                /// \brief
                /// "Message"
                static const char * const TAG_MESSAGE;

                /// \brief
                /// Entry subsystem.
                std::string subsystem;
                /// \brief
                /// Entry level.
                util::ui32 level;
                /// \brief
                /// Entry header.
                std::string header;
                /// \brief
                /// Entry message.
                std::string message;

                /// \brief
                /// ctor.
                /// \param[in] subsystem Entry subsystem.
                /// \param[in] level Entry level.
                /// \param[in] header Entry header.
                /// \param[in] message Entry message.
                Entry (
                    const std::string &subsystem_,
                    util::ui32 level_,
                    const std::string &header_,
                    const std::string &message_) :
                    subsystem (subsystem_),
                    level (level_),
                    header (header_),
                    message (message_) {}
                /// \brief
                /// ctor.
                /// \param[in] node Node that represents an Entry.
                Entry (const pugi::xml_node &node) {
                    Parse (node);
                }

                /// \brief
                /// Parse the Entry parameters from the given node.
                /// \param[in] node Node that represents an Entry.
                virtual void Parse (const pugi::xml_node &node);
                /// \brief
                /// Serialize the Entry parameters in to an XML string.
                /// \param[in] tagName Name of the containing tag.
                /// \return The XML reprentation of the Entry.
                virtual std::string ToString (
                    const char *tagName = TAG_ENTRY) const;
            };

            /// \brief
            /// Stream to dump log entries to.
            Stream::SharedPtr stream;
            /// \brief
            /// Entry tag name.
            const std::string entryTagName;

            /// \brief
            /// ctor.
            /// \param[in] stream_ Stream to dump log entries to.
            /// \param[in] entryTagName_ Entry tag name.
            StreamLogger (
                Stream::SharedPtr stream_,
                const std::string &entryTagName_ = Entry::TAG_ENTRY) :
                stream (stream_),
                entryTagName (entryTagName_) {}

            // util::Logger
            /// \brief
            /// Dump an entry to the specified stream.
            /// \param[in] subsystem Entry subsystem.
            /// \param[in] level Entry level.
            /// \param[in] header Entry header.
            /// \param[in] message Entry message.
            /// NOTE: The entry will have the following
            /// format:
            /// <entryTagName Subsystem = ""
            ///               Level = "">
            ///     <Header>...</Header>
            ///     <Message>...</Message>
            /// </entryTagName>
            virtual void Log (
                const std::string &subsystem,
                util::ui32 level,
                const std::string &header,
                const std::string &message) throw ();

            /// \brief
            /// StreamLogger is neither copy constructable, nor assignable.
            THEKOGANS_STREAM_DISALLOW_COPY_AND_ASSIGN (StreamLogger)
        };

    } // namespace stream
} // namespace thekogans

#endif // !defined (__thekogans_stream_StreamLogger_h)
