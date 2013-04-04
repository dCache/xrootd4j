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

import java.util.List;

import org.dcache.xrootd.security.XrootdBucket;
import org.dcache.xrootd.security.XrootdSecurityProtocol.BucketType;

public class AuthenticationResponse extends AbstractResponseMessage
{
    /**
     * Default authentication response, usually sent finally, if all previous
     * steps are okay
     * @param sId
     * @param status
     * @param length
     */
    public AuthenticationResponse(XrootdRequest request, int status, int length)
    {
        super(request, status, length);
    }

    /**
     * Intermediate AuthenticationResponse.
     *
     * @param sId the streamID, matching the request
     * @param status the status (usually kXR_authmore)
     * @param length
     * @param protocol the currently used authentication protocol
     * @param step the processing step
     * @param buckets list of buckets containing server-side authentication
     *                information (challenge, host certificate, etc.)
     */
    public AuthenticationResponse(XrootdRequest request,
                                  int status,
                                  int length,
                                  String protocol,
                                  int step,
                                  List<XrootdBucket> buckets) {
        super(request, status, length);

        if (protocol.length() > 4) {
            throw new IllegalArgumentException("Protocol length must not " +
                                               "exceed 4. The passed protocol is "
                                               + protocol);
        }

        putCharSequence(protocol);

        /* the protocol must be 0-padded to 4 bytes */
        int padding = 4 - protocol.getBytes().length;

        for (int i=0; i < padding; i++) {
            _buffer.writeByte(0);
        }

        putSignedInt(step);

        for (XrootdBucket bucket : buckets) {
            bucket.serialize(_buffer);
        }

        putSignedInt(BucketType.kXRS_none.getCode());
    }

}
