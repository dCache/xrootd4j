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
package org.dcache.xrootd.protocol.messages;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_statx;

import io.netty.buffer.ByteBuf;

public class StatxRequest extends AbstractXrootdRequest {

    private String[] paths;
    private String[] opaques;

    public StatxRequest(ByteBuf buffer) {
        super(buffer, kXR_statx);

        int dlen = buffer.getInt(20);
        paths = buffer.toString(24, dlen, US_ASCII).split("\n");
        opaques = new String[paths.length];

        for (int i = 0; i < paths.length; i++) {
            String path = paths[i];
            int pos = path.indexOf('?');
            if (pos > -1) {
                paths[i] = path.substring(0, pos);
                opaques[i] = path.substring(pos + 1);
            }
        }
    }

    public void setPaths(String[] paths) {
        this.paths = paths;
    }

    public String[] getPaths() {
        return paths;
    }

    public void setOpaques(String[] opaques) {
        this.opaques = opaques;
    }

    public String[] getOpaques() {
        return opaques;
    }
}
