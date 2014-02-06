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
package org.dcache.xrootd.core;

import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelHandler.Sharable;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.MessageEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;

import org.dcache.xrootd.plugins.AuthorizationFactory;
import org.dcache.xrootd.plugins.AuthorizationHandler;
import org.dcache.xrootd.protocol.XrootdProtocol.*;
import org.dcache.xrootd.protocol.messages.AbstractResponseMessage;
import org.dcache.xrootd.protocol.messages.CloseRequest;
import org.dcache.xrootd.protocol.messages.DirListRequest;
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
import org.dcache.xrootd.protocol.messages.StatRequest;
import org.dcache.xrootd.protocol.messages.StatxRequest;
import org.dcache.xrootd.protocol.messages.SyncRequest;
import org.dcache.xrootd.protocol.messages.WriteRequest;
import org.dcache.xrootd.protocol.messages.XrootdRequest;
import org.dcache.xrootd.util.OpaqueStringParser;
import org.dcache.xrootd.util.ParseException;

import static org.dcache.xrootd.protocol.XrootdProtocol.*;

@Sharable
public class XrootdAuthorizationHandler extends XrootdRequestHandler
{
    private static final Logger _log =
        LoggerFactory.getLogger(XrootdAuthorizationHandler.class);

    private final AuthorizationFactory _authorizationFactory;

    public XrootdAuthorizationHandler(AuthorizationFactory authorizationFactory)
    {
        _authorizationFactory = authorizationFactory;
    }

    @Override
    protected AbstractResponseMessage doOnStat(ChannelHandlerContext ctx,
                                               MessageEvent event,
                                               StatRequest req)
        throws XrootdException
    {
        authorize(event, req, FilePerm.READ);
        ctx.sendUpstream(event);
        return null;
    }

    @Override
    protected AbstractResponseMessage doOnStatx(ChannelHandlerContext ctx,
                                                MessageEvent event,
                                                StatxRequest req)
        throws XrootdException
    {
        if (req.getPaths().length == 0) {
            throw new XrootdException(kXR_ArgMissing, "no paths specified");
        }

        String[] paths = req.getPaths();
        String[] opaques = req.getOpaques();
        int[] flags = new int[paths.length];
        for (int i = 0; i < paths.length; i++) {
            paths[i] = authorize(event,
                                 req,
                                 FilePerm.READ,
                                 paths[i],
                                 opaques[i]);
        }
        req.setPaths(paths);

        ctx.sendUpstream(event);
        return null;
    }

    @Override
    protected AbstractResponseMessage doOnRm(ChannelHandlerContext ctx,
                                             MessageEvent event,
                                             RmRequest req)
        throws XrootdException
    {
        if (req.getPath().isEmpty()) {
            throw new XrootdException(kXR_ArgMissing, "no path specified");
        }
        authorize(event, req, FilePerm.DELETE);
        ctx.sendUpstream(event);
        return null;
    }

    @Override
    protected AbstractResponseMessage doOnRmDir(ChannelHandlerContext ctx,
                                                MessageEvent event,
                                                RmDirRequest req)
        throws XrootdException
    {
        if (req.getPath().isEmpty()) {
            throw new XrootdException(kXR_ArgMissing, "no path specified");
        }

        authorize(event, req, FilePerm.DELETE);
        ctx.sendUpstream(event);
        return null;
    }

    @Override
    protected AbstractResponseMessage doOnMkDir(ChannelHandlerContext ctx,
                                                MessageEvent event,
                                                MkDirRequest req)
        throws XrootdException
    {
        if (req.getPath().isEmpty()) {
            throw new XrootdException(kXR_ArgMissing, "no path specified");
        }

        authorize(event, req, FilePerm.WRITE);
        ctx.sendUpstream(event);
        return null;
    }

    @Override
    protected AbstractResponseMessage doOnMv(ChannelHandlerContext ctx,
                                             MessageEvent event,
                                             MvRequest req)
        throws XrootdException
    {
        String sourcePath = req.getSourcePath();
        if (sourcePath.isEmpty()) {
            throw new XrootdException(kXR_ArgMissing, "No source path specified");
        }

        String targetPath = req.getTargetPath();
        if (targetPath.isEmpty()) {
            throw new XrootdException(kXR_ArgMissing, "No target path specified");
        }

        req.setSourcePath(authorize(event,
                                    req,
                                    FilePerm.DELETE,
                                    req.getSourcePath(),
                                    req.getOpaque()));
        req.setTargetPath(authorize(event,
                                    req,
                                    FilePerm.WRITE,
                                    req.getTargetPath(),
                                    req.getOpaque()));
        ctx.sendUpstream(event);
        return null;
    }

    @Override
    protected AbstractResponseMessage doOnDirList(ChannelHandlerContext ctx,
                                                  MessageEvent event,
                                                  DirListRequest request)
        throws XrootdException
    {
        Channel channel = event.getChannel();
        InetSocketAddress localAddress =
            (InetSocketAddress) channel.getLocalAddress();

        String path = request.getPath();
        if (path.isEmpty()) {
            throw new XrootdException(kXR_ArgMissing, "no source path specified");
        }
        authorize(event, request, FilePerm.READ);
        ctx.sendUpstream(event);
        return null;
    }

    @Override
    protected AbstractResponseMessage doOnPrepare(ChannelHandlerContext ctx,
                                                  MessageEvent event,
                                                  PrepareRequest msg)
    {
        ctx.sendUpstream(event);
        return null;
    }

    @Override
    protected AbstractResponseMessage doOnOpen(ChannelHandlerContext ctx,
                                               MessageEvent event,
                                               OpenRequest msg)
        throws XrootdException
    {
        FilePerm neededPerm;
        if (msg.isNew() || msg.isReadWrite()) {
            neededPerm = FilePerm.WRITE;
        } else {
            neededPerm = FilePerm.READ;
        }
        authorize(event, msg, neededPerm);
        ctx.sendUpstream(event);
        return null;
    }

    @Override
    protected AbstractResponseMessage doOnRead(ChannelHandlerContext ctx,
                                               MessageEvent event,
                                               ReadRequest msg)
        throws XrootdException
    {
        ctx.sendUpstream(event);
        return null;
    }

    @Override
    protected AbstractResponseMessage doOnReadV(ChannelHandlerContext ctx,
                                                MessageEvent event,
                                                ReadVRequest msg)
        throws XrootdException
    {
        ctx.sendUpstream(event);
        return null;
    }

    @Override
    protected AbstractResponseMessage doOnWrite(ChannelHandlerContext ctx,
                                                MessageEvent event,
                                                WriteRequest msg)
        throws XrootdException
    {
        ctx.sendUpstream(event);
        return null;
    }

    @Override
    protected AbstractResponseMessage doOnSync(ChannelHandlerContext ctx,
                                               MessageEvent event,
                                               SyncRequest msg)
        throws XrootdException
    {
        ctx.sendUpstream(event);
        return null;
    }

    @Override
    protected AbstractResponseMessage doOnClose(ChannelHandlerContext ctx,
                                                MessageEvent event,
                                                CloseRequest msg)
        throws XrootdException
    {
        ctx.sendUpstream(event);
        return null;
    }

    @Override
    protected AbstractResponseMessage doOnProtocolRequest(ChannelHandlerContext ctx,
                                                          MessageEvent event,
                                                          ProtocolRequest msg)
        throws XrootdException
    {
        ctx.sendUpstream(event);
        return null;
    }

    @Override
    protected Object doOnQuery(ChannelHandlerContext ctx, MessageEvent event, QueryRequest req)
            throws XrootdException
    {
        switch (req.getReqcode()) {
        case kXR_Qcksum:
        case kXR_Qxattr:
            String args = req.getArgs();
            int pos = args.indexOf(OPAQUE_DELIMITER);
            String path;
            String opaque;
            if (pos > -1) {
                path = args.substring(0, pos);
                opaque = args.substring(pos + 1);
            } else {
                path = args;
                opaque = "";
            }
            req.setArgs(authorize(event, req, FilePerm.READ, path, opaque));
            break;
        }
        ctx.sendUpstream(event);
        return null;
    }

    private void authorize(MessageEvent event,
                           PathRequest request,
                           FilePerm neededPerm)
        throws XrootdException
    {
        request.setPath(authorize(event,
                                  request,
                                  neededPerm,
                                  request.getPath(),
                                  request.getOpaque()));
    }

    /**
     * Performs authorization check and path mapping.
     *
     * @param event The Netty MessageEvent for this request
     * @param request The xrootd message
     * @param neededPerm The permission level that is required for the operation
     * @param path The path to which access is requested
     * @param opaque Opaque data sent with the request
     * @return The path to which access is granted.
     * @throws XrootdException if the request is denied
     */
    private String authorize(MessageEvent event,
                             XrootdRequest request,
                             FilePerm neededPerm,
                             String path,
                             String opaque)
        throws XrootdException
    {
        try {
            Channel channel = event.getChannel();
            InetSocketAddress localAddress =
                (InetSocketAddress) channel.getLocalAddress();
            InetSocketAddress remoteAddress =
                (InetSocketAddress) channel.getRemoteAddress();

            AuthorizationHandler handler =
                _authorizationFactory.createHandler();
            return handler.authorize(request.getSubject(),
                                     localAddress,
                                     remoteAddress,
                                     path,
                                     OpaqueStringParser.getOpaqueMap(opaque),
                                     request.getRequestId(),
                                     neededPerm);
        } catch (GeneralSecurityException e) {
            throw new XrootdException(kXR_ServerError,
                                      "Authorization check failed: " +
                                      e.getMessage());
        } catch (SecurityException e) {
            throw new XrootdException(kXR_NotAuthorized,
                                      "Permission denied: " + e.getMessage());
        } catch (ParseException e) {
            throw new XrootdException(kXR_NotAuthorized,
                                      "Invalid opaque data: " + e.getMessage() +
                                      " (opaque=" + opaque + ")");
        }
    }
}
