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

#if !defined (__thekogans_stream_Socket_h)
#define __thekogans_stream_Socket_h

#include <cstring>
#include <memory>
#include <string>
#include <list>
#include "thekogans/util/TimeSpec.h"
#include "thekogans/stream/Config.h"
#include "thekogans/stream/Stream.h"
#include "thekogans/stream/Address.h"

namespace thekogans {
    namespace stream {

        /// \struct Socket Socket.h thekogans/stream/Socket.h
        ///
        /// \brief
        /// Socket is a base class for all socket derivatives. It provides
        /// all common socket apis, and let's the derivatives handle the
        /// specifics (connecting and streaming).

        struct _LIB_THEKOGANS_STREAM_DECL Socket : public Stream {
            /// \brief
            /// Convenient typedef for util::ThreadSafeRefCounted::Ptr<Socket>.
            typedef util::ThreadSafeRefCounted::Ptr<Socket> Ptr;

        private:
            /// \brief
            /// Socket family specification.
            int family;
            /// \brief
            /// Socket type specification.
            int type;
            /// \brief
            //. Socket protocol specification.
            int protocol;

        public:
            /// \brief
            /// ctor.
            /// Wrap an OS handle.
            /// \param[in] handle OS stream handle to wrap.
            Socket (THEKOGANS_UTIL_HANDLE handle = THEKOGANS_UTIL_INVALID_HANDLE_VALUE);
            /// \brief
            /// ctor.
            /// \param[in] family_ Socket family specification.
            /// \param[in] type_ Socket type specification.
            /// \param[in] protocol_ Socket protocol specification.
            Socket (
                int family_,
                int type_,
                int protocol_);
            /// \brief
            /// dtor.
            /// Socket re-implements Close, and therefore
            /// needs to call Close itself.
            virtual ~Socket ();

            // Stream
            /// \brief
            /// Return read timeout value.
            /// \return Read timeout value.
            virtual util::TimeSpec GetReadTimeout () const;
            /// \brief
            /// Set read timeout.
            /// \param[in] timeSpec Read timeout.
            virtual void SetReadTimeout (const util::TimeSpec &timeSpec);

            /// \brief
            /// Return write timeout value.
            /// \return Write timeout value.
            virtual util::TimeSpec GetWriteTimeout () const;
            /// \brief
            /// Set write timeout.
            /// \param[in] timeSpec Write timeout.
            virtual void SetWriteTimeout (const util::TimeSpec &timeSpec);

            /// \brief
            /// Return the host name.
            /// \return Host name.
            static std::string GetHostName ();

            /// \brief
            /// Return number of bytes available for reading.
            /// \return Number of bytes available for reading.
            std::size_t GetDataAvailable () const;

            /// \brief
            /// Get socket family.
            /// \return Socket family.
            inline int GetFamily () const {
                return family;
            }
            /// \brief
            /// Get socket type.
            /// \return Socket type.
            inline int GetType () const {
                return type;
            }
            /// \brief
            /// Get socket protocol.
            /// \return Socket protocol.
            inline int GetProtocol () const {
                return protocol;
            }

            /// \brief
            /// Return true if the connected peer is a local process.
            /// \return true if the connected peer is a local process.
            inline bool IsPeerLocal () const {
                return GetPeerAddress ().AddrToString () == GetHostAddress ().AddrToString ();
            }

            /// \brief
            /// Bind the socket to the given address.
            /// \param[in] address Address to bind the socket to.
            void Bind (const Address &address);

            /// \brief
            /// Get socket address.
            /// \return Socket address.
            Address GetHostAddress () const;
            /// \brief
            /// Get socket peer address.
            /// \return Socket peer address.
            Address GetPeerAddress () const;

            /// \brief
            /// Put the socket in (non-)blocking mode.
            /// \param[in] blocking true = blocking, false = non-blocking
            void SetBlocking (bool blocking);

            /// \brief
            /// Return true if level = IPPROTO_IPV6 option name = IPV6_V6ONLY is set.
            /// \return true = IPV6_V6ONLY is set, false = IPV6_V6ONLY not set.
            bool IsIPV6Only () const;
            /// \brief
            /// Set the level = IPPROTO_IPV6 option name = IPV6_V6ONLY socket option.
            /// \param[in] ipv6Only true = set, false = unset.
            void SetIPV6Only (bool ipv6Only);

            /// \brief
            /// Check if the SO_REUSEADDR option is set.
            /// \return true = SO_REUSEADDR option is set.
            bool IsReuseAddress () const;
            /// \brief
            /// Set the SO_REUSEADDR option.
            /// \param[in] reuseAddress true = set, false = unset.
            void SetReuseAddress (bool reuseAddress);

        #if defined (SO_EXCLUSIVEADDRUSE)
            /// \brief
            /// Check if the SO_EXCLUSIVEADDRUSE option is set.
            /// \return true = SO_EXCLUSIVEADDRUSE option is set.
            bool IsExclusiveAddressUse () const;
            /// \brief
            /// Set the SO_EXCLUSIVEADDRUSE option.
            /// \param[in] exclusiveAddressUse true = set, false = unset.
            void SetExclusiveAddressUse (bool exclusiveAddressUse);
        #endif // defined (SO_EXCLUSIVEADDRUSE)

        #if defined (SO_REUSEPORT) || defined (SO_REUSE_UNICASTPORT)
            /// \brief
            /// Check if the SO_REUSEPORT option is set.
            /// \return true = SO_REUSEPORT option is set.
            bool IsReusePort () const;
            /// \brief
            /// Set the SO_REUSEPORT option.
            /// \param[in] reusePort true = set, false = unset.
            void SetReusePort (bool reusePort);
        #endif // defined (SO_REUSEPORT) || defined (SO_REUSE_UNICASTPORT)

            /// \brief
            /// Return send buffer size.
            /// \return Send buffer size.
            std::size_t GetSendBufferSize () const;
            /// \brief
            /// Set send buffer size.
            /// \param[in] size Send buffer size.
            void SetSendBufferSize (std::size_t size);

            /// \brief
            /// Return receive buffer size.
            /// \return Receive buffer size.
            std::size_t GetReceiveBufferSize () const;
            /// \brief
            /// Set receive buffer size.
            /// \param[in] size Receive buffer size.
            void SetReceiveBufferSize (std::size_t size);

            /// \brief
            /// Return the last error that ocured on this socket.
            /// This api should only be used by AsyncIoEventQueue.
            /// \return Last error that ocured on this socket.
            THEKOGANS_UTIL_ERROR_CODE GetErrorCode () const;

        protected:
            // Stream
            /// \brief
            /// On Windows socket handles are closed using
            /// closesocket (not CloseHandle).
            virtual void Close ();

            /// \brief
            /// Streams are neither copy constructable, nor assignable.
            THEKOGANS_STREAM_DISALLOW_COPY_AND_ASSIGN (Socket)
        };

    } // namespace stream
} // namespace thekogans

#endif // !defined (__thekogans_stream_Socket_h)
