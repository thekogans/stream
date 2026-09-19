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

#include "thekogans/stream/Version.h"

namespace thekogans {
    namespace stream {

        _LIB_THEKOGANS_STREAM_DECL const util::Version & _LIB_THEKOGANS_STREAM_API GetVersion () {
            util::ui32 major = 0;
            util::ui32 minor = 0;
            util::ui32 patch = 0;
        #if !THEKOGANS_UTIL_IS_MACRO_EMPTY (THEKOGANS_STREAM_MAJOR_VERSION)
            major = THEKOGANS_STREAM_MAJOR_VERSION;
        #endif
        #if !THEKOGANS_UTIL_IS_MACRO_EMPTY (THEKOGANS_STREAM_MINOR_VERSION)
            minor = THEKOGANS_STREAM_MINOR_VERSION;
        #endif
        #if !THEKOGANS_UTIL_IS_MACRO_EMPTY (THEKOGANS_STREAM_PATCH_VERSION)
            patch = THEKOGANS_STREAM_PATCH_VERSION;
        #endif
            static const util::Version version (major, minor, patch);
            return version;
        }

    } // namespace stream
} // namespace thekogans
