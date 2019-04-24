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
package org.dcache.xrootd.core;

import io.netty.channel.ChannelHandler;

import org.dcache.xrootd.plugins.AuthenticationFactory;
import org.dcache.xrootd.plugins.ChannelHandlerFactory;
import org.dcache.xrootd.plugins.ProxyDelegationClient;

public class XrootdAuthenticationHandlerFactory implements ChannelHandlerFactory
{
    private final String name;
    private final AuthenticationFactory authenticationFactory;

    /*
     *  Unlike the authentication handler, which requires a separate
     *  instance per connection, the store client should
     *  be stateless, with one instance per handler type.
     */
    private final ProxyDelegationClient proxyDelegationClient;

    public XrootdAuthenticationHandlerFactory(String name,
                                              AuthenticationFactory authenticationFactory,
                                              ProxyDelegationClient proxyDelegationClient)
    {
        this.name = name;
        this.authenticationFactory = authenticationFactory;
        this.proxyDelegationClient = proxyDelegationClient;
    }

    @Override
    public String getName()
    {
        return XrootdAuthenticationHandlerProvider.PREFIX + name;
    }

    @Override
    public String getDescription()
    {
        return "Authentication handler";
    }

    @Override
    public ChannelHandler createHandler()
    {
        return new XrootdAuthenticationHandler(authenticationFactory,
                                               proxyDelegationClient);
    }
}
