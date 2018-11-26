/**
 * Copyright (C) 2011-2018 dCache.org <support@dcache.org>
 *
 * This file is part of xrootd4j.
 *
 * xrootd4j is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * xrootd4j is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with xrootd4j.  If not, see http://www.gnu.org/licenses/.
 */

package org.dcache.xrootd.security;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.dcache.xrootd.core.XrootdException;

import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_error;

/**
 * <p>Utility class for holding security requirement information.</p>
 */
public class SecurityInfo {

    /**
     * @param sec the security information included in the Login response.
     * @return list of security protocols supported by server, in the order
     *         supplied by the server.
     */
    public static List<SecurityInfo> parse(String sec)
                    throws XrootdException
    {
        List<SecurityInfo> info = new ArrayList<>();

        String[] protocols = sec.trim().split("[&]");

        String protocol;
        String version;
        String encryption;
        String[] caIdentities;

        for (int i = 1; i < protocols.length; ++i) {
            version = null;
            encryption = null;
            caIdentities = null;

            String[] parts = protocols[i].split("[,]");

            if (!parts[0].startsWith("P=")) {
                throw new XrootdException(kXR_error, "Malformed 'sec': " + sec);
            }

            protocol = parts[0].substring(2).trim();

            for (int j = 1; j < parts.length; ++j) {
                String[] keyVal = parts[j].split("[:]");
                switch (keyVal[0].toLowerCase()) {
                    case "v":
                        version = keyVal[1];
                        break;
                    case "c":
                        encryption = keyVal[1];
                        break;
                    case "ca":
                        caIdentities = keyVal[1].split("[|]");
                        break;
                }
            }

            info.add(new SecurityInfo(protocol, version, encryption, caIdentities));
        }

        return info;
    }

    private final String   protocol;
    private final String   version;
    private final String   encryption;
    private final String[] caIdentities;

    private SecurityInfo(String protocol,
                         String version,
                         String encryption,
                         String[] caIdentities)
    {
        this.protocol = protocol;
        this.version = version;
        this.encryption = encryption;
        this.caIdentities = caIdentities;
    }

    public String[] getCaIdentities()
    {
        return caIdentities;
    }

    public String getEncryption()
    {
        return encryption;
    }

    public String getProtocol()
    {
        return protocol;
    }

    public String getVersion()
    {
        return version;
    }

    public String toString()
    {
        return "(protocol " + protocol
                        + ")(version " + version
                        + ")(encryption " + encryption
                        + ")(caIdentities " + (caIdentities == null ? null :
                            Arrays.asList(caIdentities)) + ")";
    }
}
