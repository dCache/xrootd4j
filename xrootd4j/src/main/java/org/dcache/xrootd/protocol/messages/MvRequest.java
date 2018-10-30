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
package org.dcache.xrootd.protocol.messages;

import io.netty.buffer.ByteBuf;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_mv;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.kXR_secCompatible;

public class MvRequest extends AbstractXrootdRequest
{
    private String sourcePath;
    private String targetPath;
    private String opaque;

    public MvRequest(ByteBuf buffer) {
        super(buffer, kXR_mv);
        signingLevel = kXR_secCompatible;

        int dlen = buffer.getInt(20);
        int end = 24 + dlen;

        int psep = buffer.indexOf(24, end, (byte)0x20);
        int osep = buffer.indexOf(psep, end, (byte)0x3f);

        if (psep == -1) {
            throw new IllegalArgumentException("kXR_mv needs two paths!");
        }

        if (osep > -1) {
            sourcePath = buffer.toString(24,
                                          psep - 24,
                                          US_ASCII);
            targetPath = buffer.toString(psep+1,
                                          osep - (psep + 1),
                                          US_ASCII);
            opaque = buffer.toString(osep + 1,
                                      end - (osep + 1),
                                      US_ASCII);
        } else {
            sourcePath = buffer.toString(24,
                                          psep - 24,
                                          US_ASCII);
            targetPath = buffer.toString(psep+1,
                                          end - (psep + 1),
                                          US_ASCII);
            opaque = null;
        }
    }

    public void setOpaque(String opaque)
    {
        this.opaque = opaque;
    }

    public String getOpaque()
    {
        return opaque;
    }

    public void setSourcePath(String sourcePath)
    {
        this.sourcePath = sourcePath;
    }

    public String getSourcePath()
    {
        return sourcePath;
    }

    public void setTargetPath(String targetPath)
    {
        this.targetPath = targetPath;
    }

    public String getTargetPath()
    {
        return targetPath;
    }

    @Override
    public String toString()
    {
        return "mv[" + getSourcePath() + "," + getTargetPath() + "," + getOpaque() + "]";
    }
}
