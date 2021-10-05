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
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_mv;

import io.netty.buffer.ByteBuf;

public class MvRequest extends AbstractXrootdRequest {

    private String sourcePath;
    private String targetPath;
    private String sourceOpaque;
    private String targetOpaque;

    public MvRequest(ByteBuf buffer) {
        super(buffer, kXR_mv);

        int dlen = buffer.getInt(20);
        int end = 24 + dlen;

        int psep = buffer.indexOf(24, end, (byte) 0x20);

        if (psep == -1) {
            throw new IllegalArgumentException("kXR_mv needs two paths!");
        }

        String source = buffer.toString(24,
              psep - 24,
              US_ASCII);
        String target = buffer.toString(psep + 1,
              end - (psep + 1),
              US_ASCII);

        int osep = source.indexOf("?");

        if (osep > -1) {
            sourcePath = source.substring(0, osep);
            sourceOpaque = source.substring(osep + 1);
        } else {
            sourcePath = source;
        }

        osep = target.indexOf("?");

        if (osep > -1) {
            targetPath = target.substring(0, osep);
            targetOpaque = target.substring(osep + 1);
        } else {
            targetPath = target;
        }
    }

    @Deprecated
    public String getOpaque() {
        return targetOpaque;
    }

    @Deprecated
    public void setOpaque(String opaque) {
        targetOpaque = opaque;
    }

    public String getSourceOpaque() {
        return sourceOpaque;
    }

    public void setSourceOpaque(String sourceOpaque) {
        this.sourceOpaque = sourceOpaque;
    }

    public String getTargetOpaque() {
        return targetOpaque;
    }

    public void setTargetOpaque(String targetOpaque) {
        this.targetOpaque = targetOpaque;
    }

    public void setSourcePath(String sourcePath) {
        this.sourcePath = sourcePath;
    }

    public String getSourcePath() {
        return sourcePath;
    }

    public void setTargetPath(String targetPath) {
        this.targetPath = targetPath;
    }

    public String getTargetPath() {
        return targetPath;
    }

    @Override
    public String toString() {
        return "mv[" + sourcePath + ","
              + (sourceOpaque == null ? "" : "?" + sourceOpaque + ",")
              + targetPath + ","
              + (targetOpaque == null ? "" : "?" + targetOpaque + ",")
              + "]";
    }
}
