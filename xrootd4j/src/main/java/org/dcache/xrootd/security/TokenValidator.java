/**
 * Copyright (C) 2011-2021 dCache.org <support@dcache.org>
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

import io.netty.channel.ChannelHandlerContext;

import javax.security.auth.Subject;

import java.util.Optional;

import org.dcache.xrootd.core.XrootdException;

public interface TokenValidator
{
    /**
     * Handles the implementation-specific authorization procedure.
     *
     * @param ctx of the current channel
     * @param token passed into the authorization handler
     * @throws XrootdException
     */
    void validate(ChannelHandlerContext ctx, String token) throws XrootdException;

    /**
     * Determines if a token exists in the subject and returns it if true.
     */
    Optional<String> getTokenFromSubject(Subject subject);
}
