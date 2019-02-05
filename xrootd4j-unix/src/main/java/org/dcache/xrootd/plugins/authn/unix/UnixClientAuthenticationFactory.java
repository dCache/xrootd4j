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
package org.dcache.xrootd.plugins.authn.unix;

import io.netty.channel.ChannelHandler;

import java.util.Properties;

import org.dcache.xrootd.plugins.ChannelHandlerFactory;

import static org.dcache.xrootd.plugins.authn.unix.UnixClientAuthenticationHandler.PROTOCOL;

/**
 * <p>Authentication factory that returns unix security handlers to add to the
 *    third-party client channel pipeline.</p>
 */
public class UnixClientAuthenticationFactory implements ChannelHandlerFactory
{
    public UnixClientAuthenticationFactory(Properties properties)
    {
        // NOP
    }

    @Override
    public String getName() {
        return PROTOCOL;
    }

    @Override
    public String getDescription() {
        return "Unix authentication client plugin for third-party transfers";
    }

    @Override
    public ChannelHandler createHandler() {
        return new UnixClientAuthenticationHandler();
    }
}
