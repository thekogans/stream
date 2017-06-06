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

#if defined (THEKOGANS_STREAM_HAVE_PUGIXML)

#include <sstream>
#include "thekogans/util/Types.h"
#include "thekogans/util/XMLUtils.h"
#include "thekogans/stream/StreamLogger.h"

namespace thekogans {
    namespace stream {

        const char * const StreamLogger::Entry::TAG_ENTRY = "Entry";
        const char * const StreamLogger::Entry::ATTR_SUBSYSTEM = "Subsystem";
        const char * const StreamLogger::Entry::ATTR_LEVEL = "Level";
        const char * const StreamLogger::Entry::TAG_HEADER = "Header";
        const char * const StreamLogger::Entry::TAG_MESSAGE = "Message";

        void StreamLogger::Entry::Parse (const pugi::xml_node &node) {
            subsystem = util::Decodestring (node.attribute (ATTR_SUBSYSTEM).value ());
            level = util::stringToui32 (node.attribute (ATTR_LEVEL).value ());
            for (pugi::xml_node child = node.first_child ();
                    !child.empty (); child = child.next_sibling ()) {
                if (child.type () == pugi::node_element) {
                    std::string childName = child.name ();
                    if (childName == TAG_HEADER) {
                        header = util::Decodestring (child.text ().get ());
                    }
                    else if (childName == TAG_MESSAGE) {
                        message = util::Decodestring (child.text ().get ());
                    }
                }
            }
        }

        std::string StreamLogger::Entry::ToString (const char *tagName) const {
            if (tagName != 0) {
                util::Attributes attributes;
                attributes.push_back (util::Attribute (ATTR_SUBSYSTEM, subsystem));
                attributes.push_back (util::Attribute (ATTR_LEVEL, util::ui32Tostring (level)));
                std::ostringstream stream;
                stream <<
                    util::OpenTag (0, tagName, attributes, false, true) <<
                        util::OpenTag (1, TAG_HEADER) <<
                            util::Encodestring (header) <<
                        util::CloseTag (1, TAG_HEADER) <<
                        util::OpenTag (1, TAG_MESSAGE) <<
                            util::Encodestring (message) <<
                        util::CloseTag (1, TAG_MESSAGE) <<
                    util::CloseTag (0, tagName);
                return stream.str ();
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        void StreamLogger::Log (
                const std::string &subsystem,
                util::ui32 level,
                const std::string &header,
                const std::string &message) throw () {
            std::string entry = Entry (subsystem, level,
                header, message).ToString (entryTagName.c_str ());
            stream->Write (entry.c_str (), (util::ui32)entry.size ());
        }

    } // namespace stream
} // namespace thekogans

#endif // defined (THEKOGANS_STREAM_HAVE_PUGIXML)
