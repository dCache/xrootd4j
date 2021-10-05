/**
 * Copyright (C) 2011-2021 dCache.org <support@dcache.org>
 *
 * This file is part of xrootd4j.
 *
 * xrootd4j is free software: you can redistribute it and/or modify it under the terms of the GNU
 * Lesser General Public License as published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * xrootd4j is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with xrootd4j.  If
 * not, see http://www.gnu.org/licenses/.
 */
package org.dcache.xrootd.util;

import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_DataServer;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_LBalServer;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_anongpf;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_attrMeta;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_attrProxy;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_attrSuper;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_gotoTLS;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_haveTLS;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_isManager;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_isServer;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_supgpf;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_suppgrw;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_supposc;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_tlsData;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_tlsGPF;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_tlsGPFA;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_tlsLogin;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_tlsSess;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_tlsTPC;
import static org.dcache.xrootd.util.ServerProtocolFlags.TlsMode.OFF;
import static org.dcache.xrootd.util.ServerProtocolFlags.TlsMode.STRICT;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *  Server-wide settings.   These are used to determine the flags
 *  returned to the client, depending on the client information.
 *  </p>
 *
 *  These can be configured locally, or used as a placeholder
 *  for the protocol flags received by the client.
 *
 *  </p>
 *  NOTE:  as far as I can tell, the kXR_tlsTPC flag is meaningless and
 *  is not observed in the current implementation of xrootd.
 *
 *  In order to maintain uniformity, I have eliminated the "requiresTPC"
 *  setting from these flags.
 */
public class ServerProtocolFlags {

    private static final Logger LOGGER
          = LoggerFactory.getLogger(ServerProtocolFlags.class);

    public enum TlsMode {
        OFF, OPTIONAL, STRICT
    }

    private int flags = 0x0;

    private TlsMode mode;

    public ServerProtocolFlags() {
    }

    /**
     * Constructor used in conjunction with flags from remote (source)
     * server.
     *
     * @param flags received with protocol response.
     */
    public ServerProtocolFlags(int flags) {
        this.flags = flags;
        if (!requiresTLSForData() &&
              !requiresTLSForGPF() &&
              !requiresTLSForLogin() &&
              !requiresTLSForSession() &&
              !requiresTLSForTPC()) {
            mode = OFF;
        } else {
            mode = STRICT;
        }
    }

    public ServerProtocolFlags(ServerProtocolFlags serverProtocolFlags) {
        this.flags = serverProtocolFlags.flags;
        this.mode = serverProtocolFlags.mode;
    }

    public boolean allowsAnonymousGPFile() {
        boolean response = (flags & kXR_anongpf) == kXR_anongpf;
        LOGGER.trace("allowsAnonymousGPFile ? {}.", response);
        return response;
    }

    public int getFlags() {
        if (mode == OFF) {
            int shifted = (flags << 8);
            shifted = (shifted >> 8);
            LOGGER.trace("getFlags, mode is OFF, returning {}.", (shifted));
            return shifted;
        }

        return flags;
    }

    public TlsMode getMode() {
        return mode;
    }

    public boolean goToTLS() {
        boolean response = mode != OFF && (flags & kXR_gotoTLS) == kXR_gotoTLS;
        LOGGER.trace("goToTLS ? {}.", response);
        return response;
    }

    public boolean hasManagerRole() {
        boolean response = (flags & kXR_isManager) == kXR_isManager;
        LOGGER.trace("hasManagerRole ? {}.", response);
        return response;
    }

    public boolean hasMetaServerRole() {
        boolean response = (flags & kXR_attrMeta) == kXR_attrMeta;
        LOGGER.trace("hasMetaServerRole ? {}.", response);
        return response;
    }

    public boolean hasProxyServerRole() {
        boolean response = (flags & kXR_attrProxy) == kXR_attrProxy;
        LOGGER.trace("hasProxyServerRole ? {}.", response);
        return response;
    }

    public boolean hasServerRole() {
        boolean response = (flags & kXR_isServer) == kXR_isServer;
        LOGGER.trace("hasServerRole ? {}.", response);
        return response;
    }

    public boolean hasSupervisorRole() {
        boolean response = (flags & kXR_attrSuper) == kXR_attrSuper;
        LOGGER.trace("hasSupervisorRole ? {}.", response);
        return response;
    }

    public boolean isDataServer() {
        boolean response = (flags & kXR_DataServer) == kXR_DataServer;
        LOGGER.trace("isDataServer ? {}.", response);
        return response;
    }

    public boolean isLoadBalancingServer() {
        boolean response = (flags & kXR_LBalServer) == kXR_LBalServer;
        LOGGER.trace("isLoadBalancingServer ? {}.", response);
        return response;
    }

    public boolean requiresTLSForData() {
        boolean response = (flags & kXR_tlsData) == kXR_tlsData;
        LOGGER.trace("requiresTLSForData ? {}.", response);
        return response;
    }

    public boolean requiresTLSForGPF() {
        boolean response = (flags & kXR_tlsGPF) == kXR_tlsGPF;
        LOGGER.trace("requiresTLSForGPF ? {}.", response);
        return response;
    }

    public boolean requiresTLSForGPFA() {
        boolean response = (flags & kXR_tlsGPFA) == kXR_tlsGPFA;
        LOGGER.trace("requiresTLSForGPFA ? {}.", response);
        return response;
    }

    public boolean requiresTLSForLogin() {
        boolean response = (flags & kXR_tlsLogin) == kXR_tlsLogin;
        LOGGER.trace("requiresTLSForLogin ? {}.", response);
        return response;
    }

    public boolean requiresTLSForSession() {
        boolean response = (flags & kXR_tlsSess) == kXR_tlsSess;
        LOGGER.trace("requiresTLSForSession ? {}.", response);
        return response;
    }

    public boolean requiresTLSForTPC() {
        boolean response = (flags & kXR_tlsTPC) == kXR_tlsTPC;
        LOGGER.trace("requiresTLSForTPC ? {}.", response);
        return response;
    }

    public void setAllowsAnonymousGPFile(boolean value) {
        LOGGER.trace("setAllowsAnonymousGPFile {}.", value);
        if (value) {
            flags |= kXR_anongpf;
        } else {
            flags &= (~kXR_anongpf);
        }
    }

    public void setDataServer(boolean value) {
        LOGGER.trace("setDataServer {}.", value);
        if (value) {
            flags |= kXR_DataServer;
        } else {
            flags &= (~kXR_DataServer);
        }
    }

    public void setMode(TlsMode mode) {
        LOGGER.trace("setMode {}.", mode);
        this.mode = mode;
    }

    public void setGoToTLS(boolean value) {
        LOGGER.trace("setGoToTLS {}.", value);
        if (value) {
            flags |= kXR_gotoTLS;
        } else {
            flags &= (~kXR_gotoTLS);
        }
    }

    public void setLoadBalancingServer(boolean value) {
        LOGGER.trace("setLoadBalancingServer {}.", value);
        if (value) {
            flags |= kXR_LBalServer;
        } else {
            flags &= (~kXR_LBalServer);
        }
    }

    public void setManagerRole(boolean value) {
        LOGGER.trace("setManagerRole {}.", value);
        if (value) {
            flags |= kXR_isManager;
        } else {
            flags &= (~kXR_isManager);
        }
    }

    public void setMetaServerRole(boolean value) {
        LOGGER.trace("setMetaServerRole {}.", value);
        if (value) {
            flags |= kXR_attrMeta;
        } else {
            flags &= (~kXR_attrMeta);
        }
    }

    public void setProxyServerRole(boolean value) {
        LOGGER.trace("setProxyServerRole {}.", value);
        if (value) {
            flags |= kXR_attrProxy;
        } else {
            flags &= (~kXR_attrProxy);
        }
    }

    public void setRequiresTLSForData(boolean value) {
        LOGGER.trace("setRequiresTLSForData {}.", value);
        if (value) {
            flags |= kXR_tlsData;
        } else {
            flags &= (~kXR_tlsData);
        }
    }

    public void setRequiresTLSForGPF(boolean value) {
        LOGGER.trace("setRequiresTLSForGPF {}.", value);
        if (value) {
            flags |= kXR_tlsGPF;
        } else {
            flags &= (~kXR_tlsGPF);
        }
    }

    public void setRequiresTLSForGPFA(boolean value) {
        LOGGER.trace("setRequiresTLSForGPFA {}.", value);
        if (value) {
            flags |= kXR_tlsGPFA;
        } else {
            flags &= (~kXR_tlsGPFA);
        }
    }

    public void setRequiresTLSForLogin(boolean value) {
        LOGGER.trace("setRequiresTLSForLogin {}.", value);
        if (value) {
            flags |= kXR_tlsLogin;
        } else {
            flags &= (~kXR_tlsLogin);
        }
    }

    public void setRequiresTLSForSession(boolean value) {
        LOGGER.trace("setRequiresTLSForSession {}.", value);
        if (value) {
            flags |= kXR_tlsSess;
        } else {
            flags &= (~kXR_tlsSess);
        }
    }

    public void setRequiresTLSForTPC(boolean value) {
        LOGGER.trace("setRequiresTLSForTPC {}.", value);
        if (value) {
            flags |= kXR_tlsTPC;
        } else {
            flags &= (~kXR_tlsTPC);
        }
    }

    public void setServerRole(boolean value) {
        LOGGER.trace("setServerRole {}.", value);
        if (value) {
            flags |= kXR_isServer;
        } else {
            flags &= (~kXR_isServer);
        }
    }

    public void setSupervisorRole(boolean value) {
        LOGGER.trace("setSupervisorRole {}.", value);
        if (value) {
            flags |= kXR_attrSuper;
        } else {
            flags &= (~kXR_attrSuper);
        }
    }

    public void setSupportsGPFile(boolean value) {
        LOGGER.trace("setSupportsGPFile {}.", value);
        if (value) {
            flags |= kXR_suppgrw;
        } else {
            flags &= (~kXR_suppgrw);
        }
    }

    public void setSupportsPGReadWrite(boolean value) {
        LOGGER.trace("setSupportsPGReadWrite {}.", value);
        if (value) {
            flags |= kXR_supgpf;
        } else {
            flags &= (~kXR_supgpf);
        }
    }

    public void setSupportsPersistOnClose(boolean value) {
        LOGGER.trace("setSupportsPersistOnClose {}.", value);
        if (value) {
            flags |= kXR_supposc;
        } else {
            flags &= (~kXR_supposc);
        }
    }

    public void setSupportsTLS(boolean value) {
        LOGGER.trace("setSupportsTLS {}.", value);
        if (value) {
            flags |= kXR_haveTLS;
        } else {
            flags &= (~kXR_haveTLS);
        }
    }

    public boolean supportsGPFile() {
        boolean response = (flags & kXR_suppgrw) == kXR_suppgrw;
        LOGGER.trace("supportsGPFile ? {}.", response);
        return response;
    }

    public boolean supportsPGReadWrite() {
        boolean response = (flags & kXR_supgpf) == kXR_supgpf;
        LOGGER.trace("supportsPGReadWrite ? {}.", response);
        return response;
    }

    public boolean supportsPersistOnClose() {
        boolean response = (flags & kXR_supposc) == kXR_supposc;
        LOGGER.trace("supportsPersistOnClose ? {}.", response);
        return response;
    }

    public boolean supportsTLS() {
        boolean response = mode != OFF && (flags & kXR_haveTLS) == kXR_haveTLS;
        LOGGER.trace("supportsTLS ? {}.", response);
        return response;
    }

    public String toString() {
        return String.format("mode: %s, flags: %s "
                    + "(manager %s, "
                    + "meta-server %s, "
                    + "proxy-server %s, "
                    + "server %s, "
                    + "supervisor %s, "
                    + "data-server %s, "
                    + "load-balancer %s, "
                    + "tlsData %s, "
                    + "tlsGPF %s, "
                    + "tlsLogin %s, "
                    + "tlsSession %s, "
                    + "tlsTPC %s, "
                    + "goToTLS %s, "
                    + "anonGPF %s)",
              mode,
              getFlags(),
              hasManagerRole(),
              hasMetaServerRole(),
              hasProxyServerRole(),
              hasServerRole(),
              hasSupervisorRole(),
              isDataServer(),
              isLoadBalancingServer(),
              requiresTLSForData(),
              requiresTLSForGPF(),
              requiresTLSForLogin(),
              requiresTLSForSession(),
              requiresTLSForTPC(),
              goToTLS(),
              allowsAnonymousGPFile());
    }
}
