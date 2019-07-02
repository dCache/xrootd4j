/**
 * Copyright (C) 2011-2019 dCache.org <support@dcache.org>
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
package org.dcache.xrootd.util;

import java.util.Map;
import java.util.Optional;

import org.dcache.xrootd.core.XrootdException;

import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_InvalidRequest;

/**
 *  Protocol 4.0+ allows for an optional checksum type specification
 *  passed as an opaque/cgi element on the path.
 */
public class ChecksumInfo
{
    private static final String KEY = "cks.type";

    private final String           path;
    private final Optional<String> type;

    public ChecksumInfo(String args) throws XrootdException
    {
        int i = args.indexOf("?");
        if (i == -1) {
            path = args;
            type = Optional.empty();
        } else {
            path = args.substring(0, i);
            String query = args.substring(i);
            try {
                Map<String, String> map
                                = OpaqueStringParser.getOpaqueMap(query);
                type = Optional.ofNullable(map.get(KEY));
            } catch (ParseException e) {
                throw new XrootdException(kXR_InvalidRequest,
                                          "malformed checksum query part: "
                                                          + query);
            }
        }
    }

    public String getPath()
    {
        return path;
    }

    public Optional<String> getType()
    {
        return type;
    }
}
