/**
 * Copyright (C) 2011-2022 dCache.org <support@dcache.org>
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

import io.netty.buffer.ByteBuf;

import java.util.Collections;
import java.util.Map;
import java.util.Map.Entry;

import org.dcache.xrootd.protocol.messages.OpenRequest;
import org.dcache.xrootd.protocol.messages.XrootdRequest;
import org.dcache.xrootd.tpc.protocol.messages.AbstractXrootdOutboundRequest;
import org.dcache.xrootd.tpc.protocol.messages.OutboundOpenReadOnlyRequest;

import static org.dcache.xrootd.protocol.XrootdProtocol.*;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.*;

/**
 * <p>Encapsulates information about (a) the server-side requirements, and
 *    (b) whether a request needs to be signed accordingly.</p>
 */
public class SigningPolicy
{
    public static final SigningPolicy OFF = new SigningPolicy();

    private final int                   secLvl;
    private final Map<Integer, Integer> overrides;
    private final byte                  secOFrce;

    public SigningPolicy()
    {
        this(kXR_secNone, Collections.EMPTY_MAP);
    }

    public SigningPolicy(int secLvl, boolean force)
    {
        this(secLvl, force ? kXR_secOFrce : (byte)0, Collections.EMPTY_MAP);
    }

    public SigningPolicy(int secLvl,
                         Map<Integer, Integer> overrides)
    {
        this(secLvl, (byte)0, overrides);
    }

    public SigningPolicy(int secLvl,
                         byte secOFrce,
                         Map<Integer, Integer> overrides)
    {
        this.secLvl = secLvl;
        this.secOFrce = secOFrce;
        this.overrides = overrides;
    }

    public boolean isForceSigning()
    {
        return secOFrce == kXR_secOFrce;
    }

    public boolean isSigningOn()
    {
        return secLvl > kXR_secNone;
    }

    public boolean requiresSigning(XrootdRequest request)
    {
        int requestId = request.getRequestId();
        boolean readOnly = requestId == kXR_open &&
                        ((OpenRequest)request).isReadOnly();
        return requiresSigning(requestId, readOnly);
    }

    public boolean requiresSigning(AbstractXrootdOutboundRequest request)
    {
        boolean readOnly = request instanceof OutboundOpenReadOnlyRequest;
        return requiresSigning(request.getRequestId(), readOnly);
    }

    public String toString()
    {
        return "(secLvl " + secLvl
                        + ")(overrides " + overrides
                        + ")(force " + isForceSigning() + ")";
    }

    public void writeBytes(ByteBuf buffer)
    {
        buffer.writeByte(secOFrce);
        buffer.writeByte(secLvl);

        /*
         * kXR_char secvsz = length of data array, that is, size of map
         * {kXR_char,kXR_char} [reqidx,reqlvl]
         */
        buffer.writeByte(overrides.size());

        for (Entry<Integer,Integer> entry : overrides.entrySet()) {
            buffer.writeByte(entry.getKey());
            buffer.writeByte(entry.getValue());
        }
    }

    private boolean requiresSigning(int requestId, boolean readOnly)
    {
        int signingLevel;
        Integer override =  overrides.get(requestId);
        if (override == null) {
            override = kXR_signIgnore;
        }

        switch (requestId) {
            case kXR_dirlist:
            case kXR_locate:
            case kXR_prepare:
            case kXR_query:
            case kXR_read:
            case kXR_readv:
            case kXR_stat:
            case kXR_statx:
            case kXR_sync:
                signingLevel = kXR_secPedantic;
                break;
            case kXR_bind:
            case kXR_close:
            case kXR_endsess:
            case kXR_set:
            case kXR_pgwrite:
            case kXR_write:
            case kXR_writev:
                signingLevel = kXR_secIntense;
                break;
            case kXR_mkdir:
                signingLevel = kXR_secStandard;
                break;
            case kXR_open:
                if (readOnly) {
                    signingLevel = kXR_secStandard;
                } else {
                    signingLevel = kXR_secCompatible;
                }
                break;
            case kXR_chkpoint:
            case kXR_chmod:
            case kXR_fattr:
            case kXR_gpfile:
            case kXR_mv:
            case kXR_rmdir:
            case kXR_rm:
            case kXR_truncate:
                signingLevel = kXR_secCompatible;
                break;
            default:
                signingLevel = kXR_secNone;
        }

        return signingLevel != kXR_secNone &&
                        (secLvl >= signingLevel || override == kXR_signNeeded);
    }
}
