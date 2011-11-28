/**
 * Copyright (C) 2011 dCache.org <support@dcache.org>
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

import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;

import static org.dcache.xrootd.protocol.XrootdProtocol.*;
import org.dcache.xrootd.protocol.XrootdProtocol.FilePerm;
import org.dcache.xrootd.protocol.messages.*;
import org.dcache.xrootd.plugins.AuthorizationFactory;
import org.dcache.xrootd.plugins.AuthorizationHandler;
import org.dcache.xrootd.util.OpaqueStringParser;
import org.dcache.xrootd.util.ParseException;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.MessageEvent;
import org.jboss.netty.channel.ChannelHandler.Sharable;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Sharable
public class XrootdAuthorizationHandler extends XrootdRequestHandler
{
    private final static Logger _log =
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
            throw new XrootdException(kXR_NotAuthorized,
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