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

#if !defined (__thekogans_stream_Overlapped_h)
#define __thekogans_stream_Overlapped_h

#include <list>
#include "thekogans/util/Environment.h"
#include "thekogans/util/Types.h"
#include "thekogans/util/Heap.h"
#include "thekogans/stream/Config.h"

namespace thekogans {
    namespace stream {

        struct Stream;

    #if !defined (TOOLCHAIN_OS_Windows)
        /// \struct WSAOVERLAPPED Overlapped.h thekogans/stream/Overlapped.h
        ///
        /// \brief
        /// Since we pattern our implementation on Microsoft's overlapped,
        /// define a skeleton of it for Linux and OS X.

        struct WSAOVERLAPPED {
            /// \brief
            /// All we need is an error code.
            THEKOGANS_UTIL_ERROR_CODE errorCode;
            /// \brief
            /// ctor.
            WSAOVERLAPPED () :
                errorCode (0) {}
            /// \brief
            /// dtor.
            virtual ~WSAOVERLAPPED () {}
        };
    #endif // !defined (TOOLCHAIN_OS_Windows)

        /// \struct Overlapped Overlapped.h thekogans/stream/Overlapped.h
        ///
        /// \brief
        /// Overlapped extends a Windows WSAOVERLAPPED.

        struct _LIB_THEKOGANS_STREAM_DECL Overlapped : public WSAOVERLAPPED {
            /// \brief
            /// Convenient typedef for std::unique_ptr<Overlapped>.
            typedef std::unique_ptr<Overlapped> UniquePtr;

            /// \brief
            /// Convenient typedef for std::list<Overlapped::UniquePtr>.
            typedef std::list<Overlapped::UniquePtr> Queue;

            /// \brief
            /// ctor.
            Overlapped () {
            #if defined (TOOLCHAIN_OS_Windows)
                memset ((WSAOVERLAPPED *)this, 0, sizeof (WSAOVERLAPPED));
            #endif // defined (TOOLCHAIN_OS_Windows)
            }
            /// \brief
            /// dtor.
            virtual ~Overlapped () {}

            /// \brief
            /// Return the type name of this overlapped.
            /// \return Type name of this overlapped.
            virtual const char *GetType () const = 0;
            /// \brief
            ///
            virtual ssize_t Prolog (Stream & /*stream*/) throw () = 0;
            /// \brief
            virtual bool Epilog (Stream & /*stream*/) throw () {
                return true;
            }

            /// \brief
            /// Return error code.
            /// \return Error code.
            inline THEKOGANS_UTIL_ERROR_CODE GetError () const {
            #if defined (TOOLCHAIN_OS_Windows)
                return (THEKOGANS_UTIL_ERROR_CODE)Internal;
            #else // defined (TOOLCHAIN_OS_Windows)
                return errorCode;
            #endif // defined (TOOLCHAIN_OS_Windows)
            }
            /// \brief
            /// Set error code.
            /// \param[in] error Error code.
            inline void SetError (THEKOGANS_UTIL_ERROR_CODE errorCode_) {
            #if defined (TOOLCHAIN_OS_Windows)
                Internal = (DWORD)errorCode_;
            #else // defined (TOOLCHAIN_OS_Windows)
                errorCode = errorCode_;
            #endif // defined (TOOLCHAIN_OS_Windows)
            }

        #if defined (TOOLCHAIN_OS_Windows)
            /// \brief
            /// Return count of bytes read.
            /// \return Count of bytes read.
            inline util::ui32 GetCount () const {
                return InternalHigh;
            }
        #endif // defined (TOOLCHAIN_OS_Windows)
        };

        #define THEKOGANS_STREAM_DECLARE_OVERLAPPED(type)\
            typedef std::unique_ptr<type> UniquePtr;\
            THEKOGANS_UTIL_DECLARE_HEAP_WITH_LOCK (type, thekogans::util::SpinLock)\
            static const char *TYPE;\
            virtual const char *GetType () const override {\
                return TYPE;\
            }\
            THEKOGANS_STREAM_DISALLOW_COPY_AND_ASSIGN (type)\
        public:

        #define THEKOGANS_STREAM_IMPLEMENT_OVERLAPPED(type)\
            THEKOGANS_UTIL_IMPLEMENT_HEAP_WITH_LOCK (type, thekogans::util::SpinLock)\
            const char *type::TYPE = #type;

    } // namespace stream
} // namespace thekogans

#endif // !defined (__thekogans_stream_Overlapped_h)
