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
package org.dcache.xrootd.core;

import static org.dcache.xrootd.protocol.XrootdProtocol.FilePerm;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_ArgMissing;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_InvalidRequest;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_NotAuthorized;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_Qcksum;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_Qxattr;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_Unsupported;
import static org.dcache.xrootd.security.TLSSessionInfo.isTLSOn;

import io.netty.channel.ChannelHandler.Sharable;
import io.netty.channel.ChannelHandlerContext;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import org.dcache.xrootd.plugins.AuthorizationFactory;
import org.dcache.xrootd.plugins.AuthorizationHandler;
import org.dcache.xrootd.protocol.messages.CloseRequest;
import org.dcache.xrootd.protocol.messages.DirListRequest;
import org.dcache.xrootd.protocol.messages.LocateRequest;
import org.dcache.xrootd.protocol.messages.MkDirRequest;
import org.dcache.xrootd.protocol.messages.MvRequest;
import org.dcache.xrootd.protocol.messages.OpenRequest;
import org.dcache.xrootd.protocol.messages.PathRequest;
import org.dcache.xrootd.protocol.messages.PrepareRequest;
import org.dcache.xrootd.protocol.messages.ProtocolRequest;
import org.dcache.xrootd.protocol.messages.QueryRequest;
import org.dcache.xrootd.protocol.messages.ReadRequest;
import org.dcache.xrootd.protocol.messages.ReadVRequest;
import org.dcache.xrootd.protocol.messages.RmDirRequest;
import org.dcache.xrootd.protocol.messages.RmRequest;
import org.dcache.xrootd.protocol.messages.SetRequest;
import org.dcache.xrootd.protocol.messages.StatRequest;
import org.dcache.xrootd.protocol.messages.StatxRequest;
import org.dcache.xrootd.protocol.messages.SyncRequest;
import org.dcache.xrootd.protocol.messages.WriteRequest;
import org.dcache.xrootd.protocol.messages.XrootdRequest;
import org.dcache.xrootd.security.RequiresTLS;
import org.dcache.xrootd.util.OpaqueStringParser;
import org.dcache.xrootd.util.ParseException;

@Sharable
public class XrootdAuthorizationHandler extends XrootdRequestHandler {

    private final AuthorizationFactory _authorizationFactory;

    public XrootdAuthorizationHandler(AuthorizationFactory authorizationFactory) {
        _authorizationFactory = authorizationFactory;
    }

    @Override
    protected Void doOnStat(ChannelHandlerContext ctx, StatRequest req)
          throws XrootdException {
        /*
         *  A stat request may contain a file handle instead of path.
         *  In that case, we short-circuit the authorization.
         */
        switch (req.getTarget()) {
            case PATH:
                authorize(ctx, req, FilePerm.READ);
            case FHANDLE:
                break;
        }

        ctx.fireChannelRead(req);
        return null;
    }

    @Override
    protected Void doOnStatx(ChannelHandlerContext ctx, StatxRequest req)
          throws XrootdException {
        if (req.getPaths().length == 0) {
            throw new XrootdException(kXR_ArgMissing, "no paths specified");
        }

        String[] paths = req.getPaths();
        String[] opaques = req.getOpaques();
        for (int i = 0; i < paths.length; i++) {
            paths[i] = authorize(ctx,
                  req,
                  FilePerm.READ,
                  paths[i],
                  opaques[i]);
        }
        req.setPaths(paths);

        ctx.fireChannelRead(req);
        return null;
    }

    @Override
    protected Void doOnRm(ChannelHandlerContext ctx, RmRequest req)
          throws XrootdException {
        if (req.getPath().isEmpty()) {
            throw new XrootdException(kXR_ArgMissing, "no path specified");
        }
        authorize(ctx, req, FilePerm.DELETE);
        ctx.fireChannelRead(req);
        return null;
    }

    @Override
    protected Void doOnRmDir(ChannelHandlerContext ctx, RmDirRequest req)
          throws XrootdException {
        if (req.getPath().isEmpty()) {
            throw new XrootdException(kXR_ArgMissing, "no path specified");
        }

        authorize(ctx, req, FilePerm.DELETE);
        ctx.fireChannelRead(req);
        return null;
    }

    @Override
    protected Void doOnMkDir(ChannelHandlerContext ctx, MkDirRequest req)
          throws XrootdException {
        if (req.getPath().isEmpty()) {
            throw new XrootdException(kXR_ArgMissing, "no path specified");
        }

        authorize(ctx, req, FilePerm.WRITE);
        ctx.fireChannelRead(req);
        return null;
    }

    @Override
    protected Void doOnMv(ChannelHandlerContext ctx, MvRequest req)
          throws XrootdException {
        String sourcePath = req.getSourcePath();
        if (sourcePath.isEmpty()) {
            throw new XrootdException(kXR_ArgMissing, "No source path specified");
        }

        String targetPath = req.getTargetPath();
        if (targetPath.isEmpty()) {
            throw new XrootdException(kXR_ArgMissing, "No target path specified");
        }

        req.setSourcePath(authorize(ctx,
              req,
              FilePerm.DELETE,
              req.getSourcePath(),
              req.getSourceOpaque()));
        req.setTargetPath(authorize(ctx,
              req,
              FilePerm.WRITE,
              req.getTargetPath(),
              req.getTargetOpaque()));
        ctx.fireChannelRead(req);
        return null;
    }

    @Override
    protected Void doOnDirList(ChannelHandlerContext ctx, DirListRequest request)
          throws XrootdException {
        String path = request.getPath();
        if (path.isEmpty()) {
            throw new XrootdException(kXR_ArgMissing, "no source path specified");
        }
        authorize(ctx, request, FilePerm.READ);
        ctx.fireChannelRead(request);
        return null;
    }

    @Override
    protected Void doOnPrepare(ChannelHandlerContext ctx, PrepareRequest msg) {
        ctx.fireChannelRead(msg);
        return null;
    }

    @Override
    protected Void doOnLocate(ChannelHandlerContext ctx, LocateRequest msg)
          throws XrootdException {
        String path = msg.getPath();
        if (!path.startsWith("*")) {
            path = authorize(ctx, msg, FilePerm.READ, path, msg.getOpaque());
        } else if (!path.equals("*")) {
            path = authorize(ctx, msg, FilePerm.READ, path.substring(1), msg.getOpaque());
        }
        msg.setPath(path);
        ctx.fireChannelRead(msg);
        return null;
    }

    @Override
    protected Void doOnOpen(ChannelHandlerContext ctx, OpenRequest msg)
          throws XrootdException {
        authorize(ctx, msg, msg.getRequiredPermission());
        ctx.fireChannelRead(msg);
        return null;
    }

    @Override
    protected Void doOnRead(ChannelHandlerContext ctx, ReadRequest msg)
          throws XrootdException {
        ctx.fireChannelRead(msg);
        return null;
    }

    @Override
    protected Void doOnReadV(ChannelHandlerContext ctx, ReadVRequest msg)
          throws XrootdException {
        ctx.fireChannelRead(msg);
        return null;
    }

    @Override
    protected Void doOnWrite(ChannelHandlerContext ctx, WriteRequest msg)
          throws XrootdException {
        ctx.fireChannelRead(msg);
        return null;
    }

    @Override
    protected Void doOnSync(ChannelHandlerContext ctx, SyncRequest msg)
          throws XrootdException {
        ctx.fireChannelRead(msg);
        return null;
    }

    @Override
    protected Void doOnClose(ChannelHandlerContext ctx, CloseRequest msg)
          throws XrootdException {
        ctx.fireChannelRead(msg);
        return null;
    }

    @Override
    protected Void doOnProtocolRequest(ChannelHandlerContext ctx, ProtocolRequest msg)
          throws XrootdException {
        ctx.fireChannelRead(msg);
        return null;
    }

    @Override
    protected Void doOnQuery(ChannelHandlerContext ctx, QueryRequest req)
          throws XrootdException {
        switch (req.getReqcode()) {
            case kXR_Qcksum:
            case kXR_Qxattr:
                req.setPath(authorize(ctx, req,
                      FilePerm.READ,
                      req.getPath(),
                      req.getOpaque()));
                break;
        }
        ctx.fireChannelRead(req);
        return null;
    }

    @Override
    protected Void doOnSet(ChannelHandlerContext ctx, SetRequest request) throws XrootdException {
        ctx.fireChannelRead(request);
        return null;
    }

    private void authorize(ChannelHandlerContext ctx,
          PathRequest request,
          FilePerm neededPerm)
          throws XrootdException {
        request.setPath(authorize(ctx,
              request,
              neededPerm,
              request.getPath(),
              request.getOpaque()));
    }

    /**
     * Performs authorization check and path mapping.
     *
     * @param ctx The ChannelHandlerContext
     * @param request The xrootd message
     * @param neededPerm The permission level that is required for the operation
     * @param path The path to which access is requested
     * @param opaque Opaque data sent with the request
     * @return The path to which access is granted.
     * @throws XrootdException if the request is denied
     */
    private String authorize(ChannelHandlerContext ctx,
          XrootdRequest request,
          FilePerm neededPerm,
          String path,
          String opaque)
          throws XrootdException {
        try {
            InetSocketAddress destinationAddress = getDestinationAddress();
            InetSocketAddress sourceAddress = getSourceAddress();

            AuthorizationHandler handler
                  = _authorizationFactory.createHandler(ctx);

            /*
             *  check to see if we need TLS.
             */
            if (handler instanceof RequiresTLS && !isTLSOn(ctx)) {
                throw new XrootdException(kXR_Unsupported, "TLS is required "
                      + "for " + _authorizationFactory.getName());
            }

            return handler.authorize(request.getSubject(),
                  destinationAddress,
                  sourceAddress,
                  path,
                  OpaqueStringParser.getOpaqueMap(opaque),
                  request.getRequestId(),
                  neededPerm);
        } catch (GeneralSecurityException e) {
            throw new XrootdException(kXR_NotAuthorized,
                  "Authorization check failed: " +
                        e.getMessage());
        } catch (SecurityException e) {
            throw new XrootdException(kXR_NotAuthorized,
                  "Permission denied: " + e.getMessage());
        } catch (ParseException e) {
            throw new XrootdException(kXR_InvalidRequest,
                  "Invalid opaque data: " + e.getMessage());
        }
    }
}
