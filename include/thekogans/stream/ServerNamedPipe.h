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

#if !defined (__thekogans_stream_ServerNamedPipe_h)
#define __thekogans_stream_ServerNamedPipe_h

#include "thekogans/util/Environment.h"

#if defined (TOOLCHAIN_OS_Windows)

#include <memory>
#include "pugixml/pugixml.hpp"
#include "thekogans/stream/Config.h"
#include "thekogans/stream/NamedPipe.h"
#include "thekogans/stream/Address.h"

namespace thekogans {
    namespace stream {

        struct ServerNamedPipe;

        struct _LIB_THEKOGANS_STREAM_DECL ServerNamedPipeEvents : public virtual util::RefCounted {
            /// \brief
            /// Declare \see{util::RefCounted} pointers.
            THEKOGANS_UTIL_DECLARE_REF_COUNTED_POINTERS (ServerNamedPipeEvents)

            /// \brief
            /// dtor.
            virtual ~ServerNamedPipeEvents () {}

            /// \brief
            /// Called to report a connection on a \see{ServerNamedPipe}.
            /// \param[in] serverNamedPipe \see{ServerNamedPipe} on which
            /// the connection occurred.
            virtual void OnServerNamedPipeConnection (
                util::RefCounted::SharedPtr<ServerNamedPipe> serverNamedPipe) throw ();
        }

        /// \struct ServerNamedPipe ServerNamedPipe.h thekogans/stream/ServerNamedPipe.h
        ///
        /// \brief
        /// Server side named pipe. Use this class to listen for
        /// connections from \see{ClientNamedPipe} instances. ServerNamedPipe
        /// can be either stream or datagram just like sockets. While
        /// named pipes are very similar to sockets, there is one (at least)
        /// crucial difference. While a listening socket can only be used
        /// to listen for connections, and will return a new socket,
        /// a server named pipe will listen and become the other end of the
        /// connection upon receipt. To that end, if you want to be able
        /// to serve multiple ClientNamedPipes, here is a pattern to use:
        ///
        /// \code{.cpp}
        /// void EventHandler::HandleServerNamedPipeConnection (
        ///         ServerNamedPipe &serverNamedPipe) throw () {
        ///     THEKOGANS_UTIL_TRY {
        ///         // Create a new ServerNamedPipe clone.
        ///         ServerNamedPipe::SharedPtr newServerNamedPipe = serverNamedPipe.Clone ();
        ///         // Add the new ServerNamedPipe to the AsyncIoEventQueue.
        ///         // This will put the newly created named pipe in to
        ///         // listening mode.
        ///         eventQueue.AddStream (*newServerNamedPipe, *this);
        ///     }
        ///     THEKOGANS_UTIL_CATCH_AND_LOG
        /// }
        /// \endcode

        struct _LIB_THEKOGANS_STREAM_DECL ServerNamedPipe :
                public NamedPipe,
                public util::Producer<ServerNamedPipeEvents> {
            /// \brief
            /// ServerNamedPipe participates in the Stream dynamic
            /// discovery and creation.
            THEKOGANS_STREAM_DECLARE_STREAM (ServerNamedPipe)

            enum {
                /// \brief
                /// Default size of receive buffer.
                DEFAULT_BUFFER_SIZE = 32768
            };

        protected:
            /// \struct ServerNamedPipe::Context ServerNamedPipe.h thekogans/stream/ServerNamedPipe.h
            ///
            /// \brief
            /// ServerNamedPipe::Context represents the state
            /// of a ServerNamedPipe at rest. At any time you want
            /// to reconstitute a ServerNamedPipe from rest,
            /// feed a parsed (pugi::xml_node) one of:
            /// <tagName StreamType = "ServerNamedPipe">
            ///     <Address Family = "local"
            ///              Path = "Properly formatted named pipe address"/>
            ///     <PipeType>Byte/Message</PipeType>
            ///     <BufferSize>Size of receive buffer</BufferSize>
            /// </tagName>
            /// to: Stream::GetContext (const pugi::xml_node &node), and it
            /// will return back to you a properly constructed and initialized
            /// ServerNamedPipe::Context. Call Context::CreateStream () to
            /// recreate a ServerNamedPipe from rest. Where you go with
            /// it from there is entirely up to you, but may I recommend:
            /// \see{AsyncIoEventQueue}.
            struct _LIB_THEKOGANS_STREAM_DECL Context : public Stream::Context {
                /// \brief
                /// Declare \see{RefCounted} pointers.
                THEKOGANS_UTIL_DECLARE_REF_COUNTED_POINTERS (Context)

                /// \brief
                /// "ServerNamedPipe"
                static const char * const VALUE_SERVER_NAMED_PIPE;
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
                /// "BufferSize"
                static const char * const TAG_BUFFER_SIZE;

                /// \brief
                /// Address to listen on.
                Address address;
                /// \brief
                /// Pipe type (Byte/Message).
                NamedPipe::PipeType pipeType;
                /// \brief
                /// Size of receive buffer.
                DWORD bufferSize;

                /// \brief
                /// ctor. Parse the node representing a
                /// ServerNamedPipe::Context.
                /// \param[in] node pugi::xml_node representing
                /// a ServerNamedPipe::Context.
                explicit Context (const pugi::xml_node &node) :
                        Stream::Context (VALUE_SERVER_NAMED_PIPE),
                        address (Address::Empty),
                        pipeType (NamedPipe::Byte),
                        bufferSize (ServerNamedPipe::DEFAULT_BUFFER_SIZE) {
                    Parse (node);
                }
                /// \brief
                /// ctor.
                /// \param[in] address_ Address to listen on.
                /// \param[in] pipeType_ Pipe type (Byte/Message).
                /// \param[in] bufferSize_ Size of receive buffer.
                Context (
                    const Address &address_,
                    NamedPipe::PipeType pipeType_,
                    DWORD bufferSize_) :
                    address (address_),
                    pipeType (pipeType_),
                    bufferSize (bufferSize_) {}

                /// \brief
                /// Parse the node representing a
                /// ServerNamedPipe::Context.
                /// \param[in] node pugi::xml_node representing
                /// a ServerNamedPipe::Context.
                virtual void Parse (const pugi::xml_node &node);
                /// \brief
                /// Return a string representing the rest
                /// state of the ServerNamedPipe.
                /// \param[in] indentationLevel Pretty print parameter.
                /// indents the tag with 4 * indentationLevel spaces.
                /// \param[in] tagName Tag name (default to "Context").
                /// \return String representing the rest state of the
                /// ServerNamedPipe.
                virtual std::string ToString (
                    std::size_t indentationLevel = 0,
                    const char *tagName = TAG_CONTEXT) const;

                /// \brief
                /// Create a ServerNamedPipe based on the
                /// Context parameters.
                /// \return ServerNamedPipe based on the
                /// Context parametersaddress.
                virtual Stream::SharedPtr CreateStream () const {
                    return Stream::SharedPtr (
                        new ServerNamedPipe (address, pipeType, bufferSize));
                }
            };

            /// \brief
            /// Address to listen on.
            Address address;
            /// \brief
            /// Pipe type (Byte/Message).
            PipeType pipeType;
            /// \brief
            /// Size of receive buffer.
            DWORD bufferSize;

        public:
            /// \brief
            /// ctor.
            /// Wrap an OS handle.
            /// \param[in] handle OS stream handle to wrap.
            ServerNamedPipe (THEKOGANS_UTIL_HANDLE handle = THEKOGANS_UTIL_INVALID_HANDLE_VALUE) :
                NamedPipe (handle) {}
            /// \brief
            /// ctor.
            /// Create a server side named pipe.
            /// \param[in] address_ \see{Address} to listen on.
            /// \param[in] pipeType_ Byte/Message (similar to Socket/ServerNamedPipe).
            /// \param[in] bufferSize_ Size of receive buffer.
            /// NOTE: If you plan on using the ServerNamedPipe asynchronously,
            /// there is no need to call ServerNamedPipe::Connect, as
            /// AsyncIoEventQueue::AddStream will do that for you.
            ServerNamedPipe (
                const Address &address_,
                PipeType pipeType_ = Byte,
                DWORD bufferSize_ = DEFAULT_BUFFER_SIZE);

            /// \brief
            /// Listen for an incoming connection.
            /// NOTE: This api is to be used by blocking (not async)
            /// ServerNamedPipes only. An async ServerNamedPipe will
            /// start listening for an incoming connection as soon as
            /// you call \see{AsyncIoEventQueue::AddStream}, and will notify
            /// AsyncIoEventSink::HandleServerNamedPipeConnection.
            void Connect ();

            /// \brief
            /// Disconnect the client end of the named pipe.
            /// \param[in] flushBuffers Call FlushFileBuffers before disconnecting.
            void Disconnect (bool flushBuffers = true);

            /// \brief
            /// Clone this ServerNamedPipe.
            /// \return Cloned ServerNamedPipe.
            virtual ServerNamedPipe::SharedPtr Clone () const;

        protected:
            /// \brief
            /// Used by the \see{AsyncIoEventQueue} to allow the stream to
            /// initialize itself. When this function is called, the
            /// stream is already async, and Stream::AsyncInfo has
            /// been created. At this point the stream should do
            /// whatever stream specific initialization it needs to
            /// do.
            virtual void InitAsyncIo ();
            /// \brief
            /// Used by \see{AsyncIoEventQueue} to notify the stream that
            /// an overlapped operation has completed successfully.
            /// \param[in] overlapped Overlapped that completed successfully.
            virtual void HandleOverlapped (AsyncInfo::Overlapped &overlapped) throw ();

            /// \brief
            /// Streams are neither copy constructable, nor assignable.
            THEKOGANS_STREAM_DISALLOW_COPY_AND_ASSIGN (ServerNamedPipe)
        };

    } // namespace stream
} // namespace thekogans

#endif // defined (TOOLCHAIN_OS_Windows)

#endif // !defined (__thekogans_stream_ServerNamedPipe_h)
