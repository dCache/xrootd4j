/**
 * Copyright (C) 2011-2013 dCache.org <support@dcache.org>
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

import static org.dcache.xrootd.protocol.XrootdProtocol.*;
import org.jboss.netty.buffer.ChannelBuffer;

public class StatxRequest extends XrootdRequest
{
    private String[] _paths;
    private String[] _opaques;

    public StatxRequest(ChannelBuffer buffer)
    {
        super(buffer, kXR_statx);

        int dlen = buffer.getInt(20);
        _paths = buffer.toString(24, dlen, XROOTD_CHARSET).split("\n");
        _opaques = new String[_paths.length];

        for (int i = 0; i < _paths.length; i++) {
            String path = _paths[i];
            int pos = path.indexOf('?');
            if (pos > -1) {
                _paths[i] = path.substring(0, pos);
                _opaques[i] = path.substring(pos + 1);
            }
        }
    }

    public void setPaths(String[] paths)
    {
        _paths = paths;
    }

    public String[] getPaths()
    {
        return _paths;
    }

    public void setOpaques(String[] opaques)
    {
        _opaques = opaques;
    }

    public String[] getOpaques()
    {
        return _opaques;
    }
}
