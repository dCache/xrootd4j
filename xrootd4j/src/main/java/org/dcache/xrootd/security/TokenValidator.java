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
package org.dcache.xrootd.security;

import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_ArgInvalid;

import io.netty.channel.ChannelHandlerContext;
import org.dcache.xrootd.core.XrootdException;

public interface TokenValidator {

    /**
     *  By convention, the token can be prefixed in the path URL by
     *  this tag, which should be stripped away before processing.
     */
    String TOKEN_PREFIX = "Bearer%20";

    static String stripOffPrefix(String token) throws XrootdException {
        String[] parts = token.split("Bearer%20");

        /*
         *  This is a loose construal: we accept the last segment following
         *  any occurrence of the prefix as the actual token.
         */
        if (parts.length > 1) {
            token = parts[parts.length - 1];
        }

        if (TOKEN_PREFIX.equals(token)) {
            throw new XrootdException(kXR_ArgInvalid, "empty token");
        }

        return token.trim();
    }

    /**
     * Handles the implementation-specific authorization procedure.
     *
     * @param ctx of the current channel
     * @param token passed into the authorization handler
     * @throws XrootdException
     */
    void validate(ChannelHandlerContext ctx, String token) throws XrootdException;
}
