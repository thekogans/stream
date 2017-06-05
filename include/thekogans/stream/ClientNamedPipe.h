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

#if !defined (__thekogans_stream_ClientNamedPipe_h)
#define __thekogans_stream_ClientNamedPipe_h

#if defined (TOOLCHAIN_OS_Windows)

#if defined (THEKOGANS_STREAM_HAVE_PUGIXML)
    #include <pugixml.hpp>
#endif // defined (THEKOGANS_STREAM_HAVE_PUGIXML)
#include "thekogans/stream/Config.h"
#include "thekogans/stream/NamedPipe.h"
#include "thekogans/stream/Address.h"

namespace thekogans {
    namespace stream {

        /// \struct ClientNamedPipe ClientNamedPipe.h thekogans/stream/ClientNamedPipe.h
        ///
        /// \brief
        /// Client side named pipe. Use this class to connect to
        /// \see{ServerNamedPipe} instances. ClientNamedPipe can
        /// be either stream or datagram just like sockets.

        struct _LIB_THEKOGANS_STREAM_DECL ClientNamedPipe : public NamedPipe {
            /// \brief
            /// ClientNamedPipe participates in the Stream dynamic
            /// discovery and creation.
            THEKOGANS_STREAM_DECLARE_STREAM (ClientNamedPipe)

            enum {
                /// \brief
                /// Default timeout while waiting to connect (30 seconds).
                DEFAULT_TIMEOUT = 30000
            };

        private:
            /// \struct ClientNamedPipe::OpenInfo ClientNamedPipe.h thekogans/stream/ClientNamedPipe.h
            ///
            /// \brief
            /// ClientNamedPipe::OpenInfo represents the state
            /// of a ClientNamedPipe at rest. At any time you want
            /// to reconstitute a ClientNamedPipe from rest,
            /// feed a parsed (pugi::xml_node) one of:
            /// <tagName Type = "ClientNamedPipe">
            ///     <Address Family = "local"
            ///              Path = "Properly formated named pipe address."/>
            ///     <PipeType>byte or message</PipeType>
            ///     <Timeout>How long to wait for connection (default: 30 seconds)</Timeout>
            /// </tagName>
            /// to: thekogans::stream::Stream::GetOpenInfo (), and it will
            /// return back to you a properly constructed, initialized and
            /// connected ClientNamedPipe.
            struct _LIB_THEKOGANS_STREAM_DECL OpenInfo : Stream::OpenInfo {
                /// \brief
                /// Convenient typedef for std::unique_ptr<OpenInfo>.
                typedef std::unique_ptr<OpenInfo> UniquePtr;

            #if defined (THEKOGANS_STREAM_HAVE_PUGIXML)
                /// \brief
                /// "ClientNamedPipe"
                static const char * const VALUE_CLIENT_NAMED_PIPE;
                /// \brief
                /// "PipeType"
                static const char * const TAG_PIPE_TYPE;
                /// \brief
                /// "byte"
                static const char * const VALUE_BYTE;
                /// \brief
                /// "message"
                static const char * const VALUE_MESSAGE;
                /// \brief
                /// "Timeout"
                static const char * const TAG_TIMEOUT;
            #endif // defined (THEKOGANS_STREAM_HAVE_PUGIXML)

                /// \brief
                /// Address of ServerNamedPipe to connect to.
                Address address;
                /// \brief
                /// Pipe type (Byte or Message).
                PipeType pipeType;
                /// \brief
                /// Connection timeout.
                DWORD timeout;

            #if defined (THEKOGANS_STREAM_HAVE_PUGIXML)
                /// \brief
                /// ctor. Parse the node representing a
                /// ClientNamedPipe::OpenInfo.
                /// \param[in] node pugi::xml_node representing
                /// a ClientNamedPipe::OpenInfo.
                explicit OpenInfo (const pugi::xml_node &node) :
                        Stream::OpenInfo (VALUE_CLIENT_NAMED_PIPE),
                        address (Address::Empty),
                        pipeType (NamedPipe::Byte),
                        timeout (ClientNamedPipe::DEFAULT_TIMEOUT) {
                    Parse (node);
                }
            #endif // defined (THEKOGANS_STREAM_HAVE_PUGIXML)
                /// \brief
                /// ctor.
                /// \param[in] address_ Address of ServerNamedPipe to connect to.
                /// \param[in] pipeType_ Pipe type (Byte or Message).
                /// \param[in] timeout_ Connection timeout.
                OpenInfo (
                    const Address &address_,
                    PipeType pipeType_,
                    DWORD timeout_) :
                    address (address_),
                    pipeType (pipeType_),
                    timeout (timeout_) {}

            #if defined (THEKOGANS_STREAM_HAVE_PUGIXML)
                /// \brief
                /// Parse the node representing a
                /// ClientNamedPipe::OpenInfo.
                /// \param[in] node pugi::xml_node representing
                /// a ClientNamedPipe::OpenInfo.
                virtual void Parse (const pugi::xml_node &node);
                /// \brief
                /// Return a string representing the rest
                /// state of the ClientNamedPipe.
                /// \param[in] indentationLevel Pretty print parameter.
                /// indents the tag with 4 * indentationLevel spaces.
                /// \param[in] tagName Tag name (default to "OpenInfo").
                /// \return String representing the rest state of the
                /// ClientNamedPipe.
                virtual std::string ToString (
                    util::ui32 indentationLevel = 0,
                    const char *tagName = TAG_OPEN_INFO) const;
            #endif // defined (THEKOGANS_STREAM_HAVE_PUGIXML)

                /// \brief
                /// Create a ClientNamedPipe based on the OpenInfo parameters.
                /// \return ClientNamedPipe based on the OpenInfo parameters.
                virtual Stream::Ptr CreateStream () const {
                    return Stream::Ptr (
                        new ClientNamedPipe (address, pipeType, timeout));
                }
            };

        public:
            /// \brief
            /// ctor.
            /// Wrap an OS handle.
            /// \param[in] handle OS stream handle to wrap.
            ClientNamedPipe (THEKOGANS_UTIL_HANDLE handle = THEKOGANS_UTIL_INVALID_HANDLE_VALUE) :
                NamedPipe (handle) {}
            /// \brief
            /// ctor.
            /// Create a ClientNamedPipe and connect to the
            /// ServerNamedPipe at the other end of the address.
            /// \param[in] address Address of ServerNamedPipe to connect to.
            /// \param[in] pipeType Byte/Message (similar to Socket/UDPSocket).
            /// \param[in] timeout How long to wait for connection before giving up.
            ClientNamedPipe (
                const Address &address,
                PipeType pipeType = Byte,
                DWORD timeout = DEFAULT_TIMEOUT);

            /// \brief
            /// Streams are neither copy constructable, nor assignable.
            THEKOGANS_STREAM_DISALLOW_COPY_AND_ASSIGN (ClientNamedPipe)
        };

    } // namespace stream
} // namespace thekogans

#endif // defined (TOOLCHAIN_OS_Windows)

#endif // !defined (__thekogans_stream_ClientNamedPipe_h)
