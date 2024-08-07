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

#include "thekogans/util/Environment.h"
#if defined (TOOLCHAIN_OS_Windows)
    #include "thekogans/util/os/windows/WindowsHeader.h"
    #include <winsock2.h>
#else // defined (TOOLCHAIN_OS_Windows)
    #include <list>
    #include "thekogans/util/SpinLock.h"
#endif // defined (TOOLCHAIN_OS_Windows)
#include "thekogans/util/Types.h"
#include "thekogans/util/RefCounted.h"
#include "thekogans/util/Heap.h"
#include "thekogans/stream/Config.h"

namespace thekogans {
    namespace stream {

        /// \brief
        /// Forward declaration of \see{Stream}.
        struct Stream;

    #if !defined (TOOLCHAIN_OS_Windows)
        /// \struct WSAOVERLAPPED Overlapped.h thekogans/stream/Overlapped.h
        ///
        /// \brief
        /// Since we pattern our implementation on Microsoft's overlapped,
        /// define a skeleton of it for Linux and OS X.

        struct WSAOVERLAPPED {
            /// \brief
            /// Error code.
            THEKOGANS_UTIL_ERROR_CODE errorCode;
            /// \brief
            /// Number of bytes received/transfered.
            util::ui32 count;
            /// \brief
            /// ctor.
            WSAOVERLAPPED () :
                errorCode (0),
                count (0) {}
            /// \brief
            /// dtor.
            virtual ~WSAOVERLAPPED () {}
        };
    #endif // !defined (TOOLCHAIN_OS_Windows)

        /// \struct Overlapped Overlapped.h thekogans/stream/Overlapped.h
        ///
        /// \brief
        /// Overlapped extends a Windows WSAOVERLAPPED. Overlapped's job is to smooth
        /// the differences between the two different approaches to async io; Namely,
        /// the proactive approach taken by Windows and the reactive approach taken by
        /// POSIX. This 'smoothing' is done in \see{Prolog} and \see{Epilog} below.
        /// Stream library supports a hybrid model choosing to adopt the POSIX reactive
        /// approach to input and Windows proactive approach to output. You can customize
        /// that through \see{Stream::chainRead}.

        struct _LIB_THEKOGANS_STREAM_DECL Overlapped :
                public WSAOVERLAPPED,
                public util::RefCounted {
            /// \brief
            /// Declare \see{RefCounted} pointers.
            THEKOGANS_UTIL_DECLARE_REF_COUNTED_POINTERS (Overlapped)

            /// \brief
            /// ctor.
            Overlapped () {
            #if defined (TOOLCHAIN_OS_Windows)
                Internal = 0;
                InternalHigh = 0;
                Offset = 0;
                OffsetHigh = 0;
                hEvent = 0;
            #endif // defined (TOOLCHAIN_OS_Windows)
            }

            /// \brief
            /// Called by \see{Stream::ExecOverlapped} to perform async io.
            /// \return Number of bytes transfered.
            virtual ssize_t Prolog (util::RefCounted::SharedPtr<Stream> /*stream*/) throw () = 0;
            /// \brief
            /// \return true == overlapped is finished and should be retired.
            /// (on POSIX only) false == try again later.
            /// NOTE: On Windows Epilog must return true.
            virtual bool Epilog (util::RefCounted::SharedPtr<Stream> /*stream*/) throw () = 0;

        #if defined (TOOLCHAIN_OS_Windows)
            void Exec (util::RefCounted::SharedPtr<Stream> /*stream*/) throw ();
        #else // defined (TOOLCHAIN_OS_Windows)
            /// \brief
            /// Convenient typedef for std::list<Overlapped::SharedPtr>.
            struct Queue {
                std::list<Overlapped::SharedPtr> queue;

                bool Enq (Overlapped::SharedPtr overlapped);
                bool Deq ();
                Overlapped::SharedPtr Head ();
            };
            bool Exec (util::RefCounted::SharedPtr<Stream> /*stream*/) throw ();
        #endif // defined (TOOLCHAIN_OS_Windows)

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

            /// \brief
            /// Return count of bytes read.
            /// \return Number of bytes transfered.
            inline util::ui32 GetCount () const {
            #if defined (TOOLCHAIN_OS_Windows)
                return (util::ui32)InternalHigh;
            #else // defined (TOOLCHAIN_OS_Windows)
                return count;
            #endif // defined (TOOLCHAIN_OS_Windows)
            }
            /// \brief
            /// Set the number of bytes transfered.
            /// \param[in] count Count of bytes read.
            inline void SetCount (util::ui32 count_) {
            #if defined (TOOLCHAIN_OS_Windows)
                InternalHigh = (DWORD)count_;
            #else // defined (TOOLCHAIN_OS_Windows)
                count = count_;
            #endif // defined (TOOLCHAIN_OS_Windows)
            }
        };

        #define THEKOGANS_STREAM_DECLARE_OVERLAPPED(_T)\
            THEKOGANS_UTIL_DECLARE_REF_COUNTED_POINTERS (_T)\
            THEKOGANS_UTIL_DECLARE_STD_ALLOCATOR_FUNCTIONS\
            THEKOGANS_UTIL_DISALLOW_COPY_AND_ASSIGN (_T)\
        public:

        #define THEKOGANS_STREAM_IMPLEMENT_OVERLAPPED(_T)\
            THEKOGANS_UTIL_IMPLEMENT_HEAP_FUNCTIONS (_T)

    } // namespace stream
} // namespace thekogans

#endif // !defined (__thekogans_stream_Overlapped_h)
