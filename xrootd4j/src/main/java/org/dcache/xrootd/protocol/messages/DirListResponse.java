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

import java.util.Iterator;
import org.dcache.xrootd.protocol.XrootdProtocol;

public class DirListResponse extends AbstractResponseMessage
{
    public DirListResponse(XrootdRequest request, int statusCode, Iterable<String> names)
    {
        super(request, statusCode, computeResponseSize(names));

        Iterator<String> i = names.iterator();
        if (i.hasNext()) {
            putCharSequence(i.next());
            while (i.hasNext()) {
                putUnsignedChar('\n');
                putCharSequence(i.next());
            }
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

    public DirListResponse(XrootdRequest request, Iterable<String> names)
    {
        this(request, XrootdProtocol.kXR_ok, names);
    }

    /**
     * Get the size of the response based on the length of the
     * directoryListing collection.
     *
     * @param names The collection from which the size is computed
     * @return The size of the response
     */
    private static int computeResponseSize(Iterable<String> names)
    {
        int length = 0;
        for (String name: names) {
            length += name.length() + 1;
        }
        return length;
    }
}
