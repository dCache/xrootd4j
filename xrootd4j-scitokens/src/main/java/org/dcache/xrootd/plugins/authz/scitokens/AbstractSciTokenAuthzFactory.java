/**
 * Copyright (C) 2011-2022 dCache.org <support@dcache.org>
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
package org.dcache.xrootd.plugins.authz.scitokens;

import io.netty.channel.ChannelHandlerContext;
import org.dcache.xrootd.plugins.AuthorizationFactory;
import org.dcache.xrootd.plugins.AuthorizationHandler;
import org.dcache.xrootd.security.TokenValidator;

/**
 *  Needs to be subclassed to provide the implementation-specific token
 *  validator.
 */
public abstract class AbstractSciTokenAuthzFactory implements AuthorizationFactory {

    private boolean strict;

    @Override
    public AuthorizationHandler createHandler(ChannelHandlerContext ctx) {
        return new XrootdSciTokenAuthzHandler(getValidatorInstance(), strict, ctx);
    }

    @Override
    public String getDescription() {
        return "Authorizes requests based on a scitoken "
              + "passed in as path query element";
    }

    @Override
    public String getName() {
        return AbstractSciTokenAuthzProvider.NAME;
    }

    public void setStrict(boolean strict) {
        this.strict = strict;
    }

    /*
     *  Should be a new instance per call.
     */
    protected abstract TokenValidator getValidatorInstance();
}
