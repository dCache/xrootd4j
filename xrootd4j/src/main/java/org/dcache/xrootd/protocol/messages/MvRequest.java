/**
 * Copyright (C) 2011,2012 dCache.org <support@dcache.org>
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
 * License along with xrootd4j.  If not, see
 * <http://www.gnu.org/licenses/>.
 */
package org.dcache.xrootd.protocol.messages;

import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_mv;

import org.jboss.netty.buffer.ChannelBuffer;

public class MvRequest extends XrootdRequest
{
    private String _sourcePath;
    private String _targetPath;
    private String _opaque;

    public MvRequest(ChannelBuffer buffer) {
        super(buffer, kXR_mv);

        int dlen = buffer.getInt(20);
        int end = 24 + dlen;

        int psep = buffer.indexOf(24, end, (byte)0x20);
        int osep = buffer.indexOf(psep, end, (byte)0x3f);

        if (psep == -1) {
            throw new IllegalArgumentException("kXR_mv needs two paths!");
        }

        if (osep > -1) {
            _sourcePath = buffer.toString(24,
                                          psep - 24,
                                          XROOTD_CHARSET);
            _targetPath = buffer.toString(psep+1,
                                          osep - (psep + 1),
                                          XROOTD_CHARSET);
            _opaque = buffer.toString(osep + 1,
                                      end - (osep + 1),
                                      XROOTD_CHARSET);
        } else {
            _sourcePath = buffer.toString(24,
                                          psep - 24,
                                          XROOTD_CHARSET);
            _targetPath = buffer.toString(psep+1,
                                          end - (psep + 1),
                                          XROOTD_CHARSET);
            _opaque = null;
        }
    }

    public void setOpaque(String opaque)
    {
        _opaque = opaque;
    }

    public String getOpaque()
    {
        return _opaque;
    }

    public void setSourcePath(String sourcePath)
    {
        _sourcePath = sourcePath;
    }

    public String getSourcePath()
    {
        return _sourcePath;
    }

    public void setTargetPath(String targetPath)
    {
        _targetPath = targetPath;
    }

    public String getTargetPath()
    {
        return _targetPath;
    }
}
