/**
 * Copyright (C) 2011 dCache.org <support@dcache.org>
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

import java.util.List;
import org.dcache.xrootd.protocol.XrootdProtocol;

public class DirListResponse extends AbstractResponseMessage
{
    public DirListResponse(int streamid, int statusCode, List<String> names)
    {
        super(streamid, statusCode, computeResponseSize(names));

        for (int i = 0; i < names.size() - 1; i++) {
            putCharSequence(names.get(i));
            putUnsignedChar('\n');
        }

        if (!names.isEmpty()) {
            putCharSequence(names.get(names.size() - 1));

            /* Last entry in the list is terminated by a 0 rather than by
             * a \n, if not more entries follow because the message is an
             * intermediate message */
            if (statusCode == XrootdProtocol.kXR_oksofar) {
                putUnsignedChar('\n');
            } else {
                putUnsignedChar(0);
            }
        }
    }

    public DirListResponse(int streamid, List<String> names)
    {
        this(streamid, XrootdProtocol.kXR_ok, names);
    }

    /**
     * Get the size of the response based on the length of the
     * directoryListing collection.
     *
     * @param names The collection from which the size is computed
     * @return The size of the response
     */
    private static int computeResponseSize(List<String> names)
    {
        int length = 0;
        for (String name: names) {
            length += name.length() + 1;
        }
        return length;
    }
}
