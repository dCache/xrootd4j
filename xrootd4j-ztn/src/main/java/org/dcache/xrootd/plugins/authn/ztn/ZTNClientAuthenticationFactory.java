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
package org.dcache.xrootd.plugins.authn.ztn;

import io.netty.channel.ChannelHandler;

import org.dcache.xrootd.plugins.ChannelHandlerFactory;

import static org.dcache.xrootd.plugins.authn.ztn.ZTNCredential.PROTOCOL;

/**
 * <p>Authentication factory that returns ztn security handlers to add to the
 *    third-party client channel pipeline.</p>
 */
public class ZTNClientAuthenticationFactory implements ChannelHandlerFactory
{
    @Override
    public ChannelHandler createHandler()
    {
        return new ZTNClientAuthenticationHandler();
    }

    @Override
    public String getDescription()
    {
        return "ZTN authentication client plugin for third-party transfers";
    }

    @Override
    public String getName()
    {
        return PROTOCOL;
    }
}
