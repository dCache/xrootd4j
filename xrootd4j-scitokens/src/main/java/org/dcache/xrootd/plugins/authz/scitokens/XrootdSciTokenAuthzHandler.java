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
package org.dcache.xrootd.plugins.authz.scitokens;

import io.netty.channel.ChannelHandlerContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;

import java.net.InetSocketAddress;
import java.util.Map;

import org.dcache.xrootd.core.XrootdException;
import org.dcache.xrootd.plugins.AuthorizationHandler;
import org.dcache.xrootd.protocol.XrootdProtocol.FilePerm;
import org.dcache.xrootd.security.TokenValidator;

import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_InvalidRequest;

public class XrootdSciTokenAuthzHandler implements AuthorizationHandler
{
    protected static final Logger LOGGER
                    = LoggerFactory.getLogger(XrootdSciTokenAuthzHandler.class);

    /**
     * The path query name to which the SciToken value is assigned.
     */
    private static final String SCITOKEN = "authz";

    /**
     * The open call from the originating client to the destination server in
     * third-party-copy.
     */
    private static final String TPC_STAGE = "tpc.stage";

    /**
     * The initial phase of the TPC_STAGE open call.  The client does
     * not pass the path query tokens to the server, so it is
     * necessary to skip this phase with respect to token authorization.
     */
    private static final String TPC_PLACEMENT = "placement";

    /*
     * The xroot protocol states that the server can specify supporting
     * different authentication protocols via a list which the client
     * should try in order.  The xrootd4j library allows for the chaining
     * of multiple such handlers on the Netty pipeline (though currently
     * dCache only supports one protocol, either GSI or none, at a time).
     *
     * Authorization, on the other hand, takes place after the authentication
     * phase; the xrootd4j authorization handler assumes that the module it
     * loads is the only authorization procedure allowed, and there is no
     * provision for passing a failed authorization on to a
     * successive handler on the pipeline.
     *
     * We thus make provision here for failing over to "standard" behavior
     * via this property.   If it is true, then we require the presence
     * of the token.  If false, and the token is missing, we return the
     * path and allow whatever restrictions that are already in force from
     * a prior login to apply.
     */
    protected final boolean strict;

    protected final TokenValidator        validator;
    protected final ChannelHandlerContext ctx;

    /**
     * @param validator validates authorization from the serializable token.
     *                  Note that this could involve a callout to other
     *                  strategies, depending on implementation.
     * @param strict   whether to authorize in the absence of a token
     *                 by falling back to a default.
     * @param ctx      of current call
     */
    public XrootdSciTokenAuthzHandler(TokenValidator validator,
                                      boolean strict,
                                      ChannelHandlerContext ctx)
    {
        this.validator = validator;
        this.strict = strict;
        this.ctx = ctx;
    }

    @Override
    public String authorize(Subject subject,
                            InetSocketAddress localAddress,
                            InetSocketAddress remoteAddress,
                            String path,
                            Map<String, String> opaque,
                            int request,
                            FilePerm mode)
                    throws XrootdException, SecurityException
    {
        LOGGER.trace("authorize: {}, {}, {}, {}, {}, {}, {}.",
                    subject, localAddress, remoteAddress,
                    path, opaque, request, mode);

        String tpcStage = opaque.get(TPC_STAGE);
        if (TPC_PLACEMENT.equals(tpcStage)) {
            return path;
        }

        String authz = opaque.get(SCITOKEN);

        if (authz == null) {
            LOGGER.debug("no token for {}; strict? {}.", path, strict);

            if (!strict) {
                return path;
            }

            throw new XrootdException(kXR_InvalidRequest,
                                      "user provided no bearer token.");
        }

        /*
         *  Throws exception if not authorized.
         */
        validator.validate(ctx, TokenValidator.stripOffPrefix(authz));

        return path;
    }
}
