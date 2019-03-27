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

#if defined (TOOLCHAIN_OS_Windows)
    #if !defined (_WINDOWS_)
        #if !defined (WIN32_LEAN_AND_MEAN)
            #define WIN32_LEAN_AND_MEAN
        #endif // !defined (WIN32_LEAN_AND_MEAN)
        #if !defined (NOMINMAX)
            #define NOMINMAX
        #endif // !defined (NOMINMAX)
        #include <windows.h>
    #endif // !defined (_WINDOWS_)
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <iphlpapi.h>
#elif defined (TOOLCHAIN_OS_OSX)
    #include <libproc.h>
    #include <sys/sysctl.h>
    #include <sys/proc.h>
    #include <sys/proc_info.h>
#endif // defined (TOOLCHAIN_OS_Windows)
#include <list>
#include "thekogans/util/ChildProcess.h"
#include "thekogans/util/Exception.h"
#include "thekogans/util/LoggerMgr.h"
#include "thekogans/stream/ServerTCPSocket.h"
#include "thekogans/stream/tcpecho/server/Server.h"

namespace thekogans {
    namespace stream {
        namespace tcpecho {
            namespace server {

                void Server::Start (
                        const std::list<Address> &addresses,
                        bool reuseAddress,
                        util::ui32 maxPendingConnections,
                        util::i32 priority,
                        util::ui32 affinity) {
                    if (done) {
                        if (!addresses.empty ()) {
                            eventQueue.reset (new AsyncIoEventQueue ());
                            for (std::list<Address>::const_iterator
                                    it = addresses.begin (),
                                    end = addresses.end (); it != end; ++it) {
                                eventQueue->AddStream (
                                    *ServerTCPSocket::Ptr (
                                        new ServerTCPSocket (
                                            *it, reuseAddress, maxPendingConnections)),
                                    *this);
                                THEKOGANS_UTIL_LOG_DEBUG ("Listening on: %s:%u\n",
                                    (*it).AddrToString ().c_str (), (*it).GetPort ());
                            }
                            done = false;
                            Create (priority, affinity);
                        }
                        else {
                            THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                                "%s", "Must supply at least one address to listen on.");
                        }
                    }
                    else {
                        THEKOGANS_UTIL_LOG_WARNING (
                            "%s\n", "Server is already running.");
                    }
                }

                void Server::Stop () {
                    if (!done) {
                        done = true;
                        jobQueue.Stop ();
                        eventQueue->Break ();
                        Wait ();
                        eventQueue.reset ();
                    }
                    else {
                        THEKOGANS_UTIL_LOG_WARNING (
                            "%s\n", "Server is not running.");
                    }
                }

                void Server::Run () throw () {
                    while (!done) {
                        THEKOGANS_UTIL_TRY {
                            eventQueue->WaitForEvents ();
                        }
                        THEKOGANS_UTIL_CATCH_AND_LOG
                    }
                    THEKOGANS_UTIL_LOG_DEBUG ("%s\n", "Server thread is exiting.");
                }

                void Server::HandleStreamError (
                        Stream &stream,
                        const util::Exception &exception) throw () {
                    THEKOGANS_UTIL_LOG_ERROR ("%s\n", exception.Report ().c_str ());
                    THEKOGANS_UTIL_TRY {
                        eventQueue->DeleteStream (stream);
                    }
                    THEKOGANS_UTIL_CATCH_AND_LOG
                }

                namespace {
                    std::string GetPeerProcessPath (TCPSocket &socket) {
                        Address peerAddress = socket.GetPeerAddress ();
                        Address hostAddress = socket.GetHostAddress ();
                        if (peerAddress.AddrToString () == hostAddress.AddrToString ()) {
                            util::ui16 peerPort = peerAddress.GetPort ();
                            util::ui16 hostPort = hostAddress.GetPort ();
                        #if defined (TOOLCHAIN_OS_Windows)
                            int family = socket.GetFamily ();
                            if (family == AF_INET) {
                                struct TCPTable {
                                    PMIB_TCPTABLE2 tcpTable;
                                    std::size_t count;

                                    TCPTable () :
                                            tcpTable ((MIB_TCPTABLE2 *)malloc (sizeof (MIB_TCPTABLE2))),
                                            count (0) {
                                        if (tcpTable != 0) {
                                            ULONG size = sizeof (MIB_TCPTABLE2);
                                            DWORD errorCode = GetTcpTable2 (tcpTable, &size, TRUE);
                                            if (errorCode != NO_ERROR) {
                                                if (errorCode == ERROR_INSUFFICIENT_BUFFER) {
                                                    free (tcpTable);
                                                    tcpTable = (MIB_TCPTABLE2 *)malloc (size);
                                                    if (tcpTable != 0) {
                                                        DWORD errorCode = GetTcpTable2 (tcpTable, &size, TRUE);
                                                        if (errorCode == NO_ERROR) {
                                                            count = tcpTable->dwNumEntries;
                                                        }
                                                        else {
                                                            free (tcpTable);
                                                            THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (errorCode);
                                                        }
                                                    }
                                                    else {
                                                        THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                                                            THEKOGANS_UTIL_OS_ERROR_CODE_ENOMEM);
                                                    }
                                                }
                                                else {
                                                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (errorCode);
                                                }
                                            }
                                        }
                                        else {
                                            THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                                                THEKOGANS_UTIL_OS_ERROR_CODE_ENOMEM);
                                        }
                                    }
                                    ~TCPTable () {
                                        free (tcpTable);
                                    }
                                } tcpTable;
                                for (std::size_t i = 0, count = tcpTable.count; i < count; ++i) {
                                    if (tcpTable.tcpTable->table[i].dwState == MIB_TCP_STATE_ESTAB) {
                                        util::ui16 localPort = (util::ui16)ntohs ((u_short)tcpTable.tcpTable->table[i].dwLocalPort);
                                        util::ui16 remotePort = (util::ui16)ntohs ((u_short)tcpTable.tcpTable->table[i].dwRemotePort);
                                        if (localPort == peerPort && remotePort == hostPort) {
                                            return util::GetProcessPath (tcpTable.tcpTable->table[i].dwOwningPid);
                                        }
                                    }
                                }
                            }
                            else if (family == AF_INET6) {
                                struct TCP6Table {
                                    PMIB_TCP6TABLE2 tcp6Table;
                                    std::size_t count;

                                    TCP6Table () :
                                            tcp6Table ((MIB_TCP6TABLE2 *)malloc (sizeof (MIB_TCP6TABLE2))),
                                            count (0) {
                                        if (tcp6Table != 0) {
                                            ULONG size = sizeof (MIB_TCP6TABLE2);
                                            DWORD errorCode = GetTcp6Table2 (tcp6Table, &size, TRUE);
                                            if (errorCode != NO_ERROR) {
                                                if (errorCode == ERROR_INSUFFICIENT_BUFFER) {
                                                    free (tcp6Table);
                                                    tcp6Table = (MIB_TCP6TABLE2 *)malloc (size);
                                                    if (tcp6Table != 0) {
                                                        DWORD errorCode = GetTcp6Table2 (tcp6Table, &size, TRUE);
                                                        if (errorCode == NO_ERROR) {
                                                            count = tcp6Table->dwNumEntries;
                                                        }
                                                        else {
                                                            free (tcp6Table);
                                                            THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (errorCode);
                                                        }
                                                    }
                                                    else {
                                                        THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                                                            THEKOGANS_UTIL_OS_ERROR_CODE_ENOMEM);
                                                    }
                                                }
                                                else {
                                                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (errorCode);
                                                }
                                            }
                                        }
                                        else {
                                            THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                                                THEKOGANS_UTIL_OS_ERROR_CODE_ENOMEM);
                                        }
                                    }
                                    ~TCP6Table () {
                                        free (tcp6Table);
                                    }
                                } tcp6Table;
                                for (std::size_t i = 0, count = tcp6Table.count; i < count; ++i) {
                                    if (tcp6Table.tcp6Table->table[i].dwState == MIB_TCP6_STATE_ESTAB) {
                                        util::ui16 localPort = (util::ui16)ntohs ((u_short)tcp6Table.tcp6Table->table[i].dwLocalPort);
                                        util::ui16 remotePort = (util::ui16)ntohs ((u_short)tcp6Table.tcp6Table->table[i].dwRemotePort);
                                        if (localPort == peerPort && remotePort == hostPort) {
                                            return util::GetProcessPath (tcp6Table.tcp6Table->table[i].dwOwningPid);
                                        }
                                    }
                                }
                            }
                        #elif defined (TOOLCHAIN_OS_Linux)
                        #elif defined (TOOLCHAIN_OS_OSX)
                            struct Processes {
                                kinfo_proc *processes;
                                std::size_t count;

                                Processes () :
                                        processes (0),
                                        count (0) {
                                    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
                                    std::size_t length = 0;
                                    if (sysctl (mib, 4, 0, &length, 0, 0) != -1) {
                                        processes = (kinfo_proc *)malloc (length);
                                        if (processes != 0) {
                                            if (sysctl (mib, 4, processes, &length, 0, 0) != -1) {
                                                count = length / sizeof (kinfo_proc);
                                            }
                                            else {
                                                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                                                    THEKOGANS_UTIL_OS_ERROR_CODE);
                                            }
                                        }
                                        else {
                                            THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                                                THEKOGANS_UTIL_OS_ERROR_CODE_ENOMEM);
                                        }
                                    }
                                    else {
                                        THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                                            THEKOGANS_UTIL_OS_ERROR_CODE);
                                    }
                                }
                                ~Processes () {
                                    free (processes);
                                }

                                inline std::size_t size () const {
                                    return count;
                                }

                                inline const kinfo_proc &operator [] (std::size_t index) const {
                                    if (index < count) {
                                        return processes[index];
                                    }
                                    else {
                                        THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                                            THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
                                    }
                                }
                            } processes;
                            for (std::size_t i = 0, count = processes.size (); i < count; ++i) {
                                struct FileDescriptors {
                                    proc_fdinfo *fileDescriptors;
                                    std::size_t count;

                                    explicit FileDescriptors (pid_t pid) :
                                            fileDescriptors (0),
                                            count (0) {
                                        int length = proc_pidinfo (pid, PROC_PIDLISTFDS, 0, 0, 0);
                                        if (length != -1) {
                                            fileDescriptors = (proc_fdinfo *)malloc (length);
                                            if (fileDescriptors != 0) {
                                                length = proc_pidinfo (pid, PROC_PIDLISTFDS, 0, fileDescriptors, length);
                                                if (length != -1) {
                                                    count = length / PROC_PIDLISTFD_SIZE;
                                                }
                                                else {
                                                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                                                        THEKOGANS_UTIL_OS_ERROR_CODE);
                                                }
                                            }
                                            else {
                                                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                                                    THEKOGANS_UTIL_OS_ERROR_CODE_ENOMEM);
                                            }
                                        }
                                        else {
                                            THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                                                THEKOGANS_UTIL_OS_ERROR_CODE);
                                        }
                                    }

                                    ~FileDescriptors () {
                                        free (fileDescriptors);
                                    }

                                    inline std::size_t size () const {
                                        return count;
                                    }

                                    inline const proc_fdinfo &operator [] (std::size_t index) const {
                                        if (index < count) {
                                            return fileDescriptors[index];
                                        }
                                        else {
                                            THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                                                THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
                                        }
                                    }
                                } fileDescriptors (processes[i].kp_proc.p_pid);
                                for (std::size_t j = 0, count = fileDescriptors.size (); j < count; ++j) {
                                    if (fileDescriptors[j].proc_fdtype == PROX_FDTYPE_SOCKET) {
                                        socket_fdinfo socketInfo;
                                        if (proc_pidfdinfo (
                                                    processes[i].kp_proc.p_pid,
                                                    fileDescriptors[j].proc_fd,
                                                    PROC_PIDFDSOCKETINFO,
                                                    &socketInfo,
                                                    PROC_PIDFDSOCKETINFO_SIZE) == PROC_PIDFDSOCKETINFO_SIZE &&
                                                (socketInfo.psi.soi_family == AF_INET || socketInfo.psi.soi_family == AF_INET6) &&
                                                socketInfo.psi.soi_kind == SOCKINFO_TCP) {
                                            util::ui16 localPort = (util::ui16)ntohs (socketInfo.psi.soi_proto.pri_tcp.tcpsi_ini.insi_lport);
                                            util::ui16 remotePort = (util::ui16)ntohs (socketInfo.psi.soi_proto.pri_tcp.tcpsi_ini.insi_fport);
                                            if (localPort == peerPort && remotePort == hostPort) {
                                                return util::GetProcessPath (processes[i].kp_proc.p_pid);
                                            }
                                        }
                                    }
                                }
                            }
                        #endif // defined (TOOLCHAIN_OS_Windows)
                        }
                        return peerAddress.AddrToString ();
                    }
                }

                void Server::HandleServerTCPSocketConnection (
                        ServerTCPSocket &serverTCPSocket,
                        TCPSocket::Ptr connection) throw () {
                    THEKOGANS_UTIL_TRY {
                        THEKOGANS_UTIL_LOG_DEBUG (
                            "Received connection request from: %s\n",
                            GetPeerProcessPath (*connection).c_str ());
                        eventQueue->AddStream (*connection, *this, 0);
                    }
                    THEKOGANS_UTIL_CATCH_AND_LOG
                }

                void Server::HandleStreamDisconnect (Stream &stream) throw () {
                    THEKOGANS_UTIL_LOG_DEBUG ("%s\n", "Connection closed.");
                    THEKOGANS_UTIL_TRY {
                        eventQueue->DeleteStream (stream);
                    }
                    THEKOGANS_UTIL_CATCH_AND_LOG
                }

                void Server::HandleStreamRead (
                        Stream &stream,
                        util::Buffer buffer) throw () {
                    THEKOGANS_UTIL_LOG_DEBUG (
                        "Received data: %u\n",
                        buffer.GetDataAvailableForReading ());
                    THEKOGANS_UTIL_TRY {
                        if (!buffer.IsEmpty ()) {
                            struct WriteJob : public util::RunLoop::Job {
                                Stream::Ptr stream;
                                util::Buffer buffer;
                                WriteJob (
                                    Stream &stream_,
                                    util::Buffer buffer_) :
                                    stream (&stream_),
                                    buffer (std::move (buffer_)) {}
                                // util::RunLoop::Job
                                virtual void Execute (const THEKOGANS_UTIL_ATOMIC<bool> &done) throw () {
                                    if (!ShouldStop (done)) {
                                        THEKOGANS_UTIL_TRY {
                                            stream->WriteBuffer (std::move (buffer));
                                        }
                                        THEKOGANS_UTIL_CATCH_AND_LOG
                                    }
                                }
                            };
                            jobQueue.EnqJob (
                                util::RunLoop::Job::Ptr (
                                    new WriteJob (stream, std::move (buffer))));
                        }
                    }
                    THEKOGANS_UTIL_CATCH_AND_LOG
                }

            } // namespace server
        } // namespace tcpecho
    } // namespace stream
} // namespace thekogans
