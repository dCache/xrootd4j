/**
 * Copyright (C) 2011,2012 dCache.org <support@dcache.org>
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
package org.dcache.xrootd.standalone;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.FileChannel;

import java.util.List;
import java.util.ArrayList;
import java.util.Arrays;

import org.apache.commons.io.FilenameUtils;

import org.dcache.xrootd.core.XrootdRequestHandler;
import org.dcache.xrootd.core.XrootdException;
import static org.dcache.xrootd.protocol.XrootdProtocol.*;
import org.dcache.xrootd.protocol.messages.*;
import org.dcache.xrootd.protocol.messages.GenericReadRequestMessage.EmbeddedReadRequest;
import org.dcache.xrootd.util.FileStatus;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.ChannelStateEvent;
import org.jboss.netty.channel.ExceptionEvent;
import org.jboss.netty.channel.MessageEvent;
import org.jboss.netty.channel.group.ChannelGroup;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DataServerHandler extends XrootdRequestHandler
{
    private final static Logger _log =
        LoggerFactory.getLogger(DataServerHandler.class);

    private final ChannelGroup _allChannels;

    private final List<RandomAccessFile> _openFiles =
        new ArrayList<RandomAccessFile>();

    private final DataServerConfiguration _configuration;

    public DataServerHandler(DataServerConfiguration configuration,
                             ChannelGroup allChannels)
    {
        _configuration = configuration;
        _allChannels = allChannels;
    }

    @Override
    public void channelOpen(ChannelHandlerContext ctx, ChannelStateEvent e)
    {
        // Add all open channels to the global group so that they are
        // closed on shutdown.
        _allChannels.add(e.getChannel());
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx,
                                ExceptionEvent e)
    {
        Throwable t = e.getCause();
        if (t instanceof ClosedChannelException) {
            _log.info("Connection closed");
        } else if (t instanceof RuntimeException || t instanceof Error) {
            Thread me = Thread.currentThread();
            me.getUncaughtExceptionHandler().uncaughtException(me, t);
        } else {
            _log.warn(t.toString());
        }
        // TODO: If not already closed, we should probably close the
        // channel.
    }

    @Override
    protected StatResponse doOnStat(ChannelHandlerContext ctx,
                                    MessageEvent event,
                                    StatRequest req)
        throws XrootdException
    {
        File file = getFile(req.getPath());
        if (!file.exists()) {
            return new StatResponse(req.getStreamId(),
                                    FileStatus.FILE_NOT_FOUND);
        } else {
            FileStatus fs = getFileStatusOf(file);
            return new StatResponse(req.getStreamId(), fs);
        }
    }

    @Override
    protected StatxResponse doOnStatx(ChannelHandlerContext ctx,
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
            File file = getFile(paths[i]);
            if (!file.exists()) {
                flags[i] = kXR_other;
            } else {
                flags[i] = getFileStatusFlagsOf(file);
            }
        }

        return new StatxResponse(req.getStreamId(), flags);
    }

    @Override
    protected OkResponse doOnRm(ChannelHandlerContext ctx,
                                MessageEvent e,
                                RmRequest req)
        throws XrootdException
    {
        if (req.getPath().isEmpty()) {
            throw new XrootdException(kXR_ArgMissing, "no path specified");
        }

        File file = getFile(req.getPath());
        if (!file.exists()) {
            throw new XrootdException(kXR_NotFound,
                                      "No such directory or file: " + file);
        } else if (!file.isFile()) {
            throw new XrootdException(kXR_NotFile,
                                      "Not a file: " + file);
        } else if (!file.delete()) {
            throw new XrootdException(kXR_IOError,
                                      "Failed to delete file: " + file);
        }
        return withOk(req);
    }

    @Override
    protected OkResponse doOnRmDir(ChannelHandlerContext ctx, MessageEvent e,
                                   RmDirRequest req)
        throws XrootdException
    {
        if (req.getPath().isEmpty()) {
            throw new XrootdException(kXR_ArgMissing, "no path specified");
        }

        File file = getFile(req.getPath());
        if (!file.exists()) {
            throw new XrootdException(kXR_NotFound,
                                      "No such directory or file: " + file);
        } else if (!file.isDirectory()) {
            throw new XrootdException(kXR_IOError,
                                      "Not a directory: " + file);
        } else if (!file.delete()) {
            throw new XrootdException(kXR_IOError,
                                      "Failed to delete dirctory: " + file);
        }
        return withOk(req);
    }

    @Override
    protected OkResponse doOnMkDir(ChannelHandlerContext ctx,
                                   MessageEvent e,
                                   MkDirRequest req)
        throws XrootdException
    {
        if (req.getPath().isEmpty()) {
            throw new XrootdException(kXR_ArgMissing, "no path specified");
        }

        File file = getFile(req.getPath());
        if (file.exists()) {
            throw new XrootdException(kXR_IOError, "Path exists: " + file);
        }
        if (req.shouldMkPath()) {
            if (!file.mkdirs()) {
                throw new XrootdException(kXR_IOError,
                                          "Failed to create directories: " + file);
            }
        } else {
            if (!file.mkdir()) {
                throw new XrootdException(kXR_IOError,
                                          "Failed to create directory: " + file);
            }
        }
        return withOk(req);
    }

    @Override
    protected OkResponse doOnMv(ChannelHandlerContext ctx, MessageEvent e,
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

        File sourceFile = getFile(req.getSourcePath());
        File targetFile = getFile(req.getTargetPath());
        if (!sourceFile.renameTo(targetFile)) {
            throw new XrootdException(kXR_IOError, "Failed to move file");
        }
        return withOk(req);
    }

    @Override
    protected DirListResponse doOnDirList(ChannelHandlerContext context,
                                          MessageEvent event,
                                          DirListRequest request)
        throws XrootdException
    {
        String listPath = request.getPath();
        if (listPath.isEmpty()) {
            throw new XrootdException(kXR_ArgMissing, "no source path specified");
        }

        File dir = getFile(listPath);
        String[] list = dir.list();
        if (list == null) {
            throw new XrootdException(kXR_NotFound, "No such directory: " + dir);
        }
        return new DirListResponse(request.getStreamId(),
                                   kXR_ok, Arrays.asList(list));
    }

    @Override
    protected OkResponse doOnPrepare(ChannelHandlerContext ctx, MessageEvent e,
                                     PrepareRequest msg)
    {
        return withOk(msg);
    }

    /**
     * Obtains the right mover instance using an opaque token in the
     * request and instruct the mover to open the file in the request.
     * Associates the mover with the file-handle that is produced during
     * processing
     */
    @Override
    protected OpenResponse doOnOpen(ChannelHandlerContext ctx,
                                    MessageEvent event,
                                    OpenRequest msg)
        throws XrootdException
    {
        int options = msg.getOptions();

        try {
            File file = getFile(msg.getPath());
            if (file.isDirectory()) {
                throw new XrootdException(kXR_isDirectory, "Not a file: " + file);
            }

            File parent = file.getParentFile();

            RandomAccessFile raf;
            if (msg.isReadWrite()) {
                if (msg.isMkPath() && !parent.exists() && !parent.mkdirs()) {
                    throw new XrootdException(kXR_IOError, "Failed to create directories: " + parent);
                }
                if (msg.isNew() && !file.createNewFile()) {
                    throw new XrootdException(kXR_IOError, "Failed to create file: " + file);
                }
                raf = new RandomAccessFile(file, "rw");
            } else {
                raf = new RandomAccessFile(file, "r");
            }

            try {
                if (msg.isReadWrite() && msg.isDelete()) {
                    raf.setLength(0);
                }

                FileStatus stat = null;
                if (msg.isRetStat()) {
                    stat = getFileStatusOf(file);
                }

                int fd = addOpenFile(raf);
                raf = null;
                return new OpenResponse(msg.getStreamId(),
                                        fd,
                                        null,
                                        null,
                                        stat);
            } finally {
                if (raf != null) {
                    raf.close();
                }
            }
        } catch (IOException e) {
            throw new XrootdException(kXR_IOError, e.getMessage());
        }
    }

    /**
     * Use the file descriptor retrieved from the mover upon open and let it
     * obtain a reader object on the pool. The reader object will be placed
     * in a queue, from which it can be taken when sending read information
     * to the client.
     * @param ctx Received from the netty pipeline
     * @param event Received from the netty pipeline
     * @param msg The actual request
     */
    @Override
    protected ReadResponse doOnRead(ChannelHandlerContext ctx,
                                    MessageEvent event,
                                    ReadRequest msg)
        throws XrootdException
    {
        try {
            int id = msg.getStreamId();
            int fd = msg.getFileHandle();
            long offset = msg.getReadOffset();
            int length = msg.bytesToRead();

            RandomAccessFile raf = getOpenFile(fd);
            FileChannel channel = raf.getChannel();
            channel.position(offset);
            ReadResponse response = new ReadResponse(id, length);
            while (length > 0) {
                int len = response.writeBytes(channel, length);
                if (len == -1) {
                    break;
                }
                length -= len;
            }
            response.setIncomplete(false);
            return response;
        } catch (IOException e) {
            throw new XrootdException(kXR_IOError, e.getMessage());
        }
    }

    /**
     * Vector reads consist of several embedded read requests, which can even
     * contain different file handles. All the descriptors for the file
     * handles are looked up and passed to a vector reader. The vector reader
     * will use the descriptors connection to the mover that "owns" them to
     * update the mover's meta-information such as the number of bytes
     * transferred or the time of the last update.
     *
     * @param ctx received from the netty pipeline
     * @param event received from the netty pipeline
     * @param msg The actual request.
     */
    @Override
    protected ReadResponse doOnReadV(ChannelHandlerContext ctx,
                                     MessageEvent event,
                                     ReadVRequest msg)
        throws XrootdException
    {
        try {
            EmbeddedReadRequest[] requests = msg.getReadRequestList();

            if (requests == null || requests.length == 0) {
                throw new XrootdException(kXR_ArgMissing,
                                          "Request contains no vector");
            }

            ReadResponse response = new ReadResponse(msg.getStreamId(), 0);

            for (EmbeddedReadRequest request: requests) {
                response.writeBytes(request);

                long offset = request.getOffset();
                long end = offset + request.BytesToRead();
                FileChannel channel =
                    getOpenFile(request.getFileHandle()).getChannel();
                channel.position(offset);
                while (offset < end) {
                    int read =
                        response.writeBytes(channel, (int) (end - offset));
                    offset += read;
                }
            }
            response.setIncomplete(false);
            return response;
        } catch (IOException e) {
            throw new XrootdException(kXR_IOError, e.getMessage());
        }
    }

    /**
     * Retrieves the file descriptor obtained upon open and invokes
     * its write operation. The file descriptor will propagate necessary
     * function calls to the mover.
     *
     * @param ctx received from the netty pipeline
     * @param event received from the netty pipeline
     * @param msg the actual request
     */
    @Override
    protected OkResponse doOnWrite(ChannelHandlerContext ctx,
                                   MessageEvent event,
                                   WriteRequest msg)
        throws XrootdException
    {
        try {
            FileChannel channel =
                getOpenFile(msg.getFileHandle()).getChannel();
            channel.position(msg.getWriteOffset());
            msg.getData(channel);
            return withOk(msg);
        } catch (IOException e) {
            throw new XrootdException(kXR_IOError, e.getMessage());
        }
    }

    /**
     * Retrieves the right mover based on the request's file-handle and
     * invokes its sync-operation.
     *
     * @param ctx received from the netty pipeline
     * @param event received from the netty pipeline
     * @param msg The actual request
     */
    @Override
    protected OkResponse doOnSync(ChannelHandlerContext ctx,
                                  MessageEvent event,
                                  SyncRequest msg)
        throws XrootdException
    {
        try {
            getOpenFile(msg.getFileHandle()).getFD().sync();
            return withOk(msg);
        } catch (IOException e) {
            throw new XrootdException(kXR_IOError, e.getMessage());
        }
    }

    /**
     * Retrieves the right descriptor based on the request's file-handle and
     * invokes its close information.
     *
     * @param ctx received from the netty pipeline
     * @param event received from the netty pipeline
     * @param msg The actual request
     */
    @Override
    protected OkResponse doOnClose(ChannelHandlerContext ctx,
                                   MessageEvent event,
                                   CloseRequest msg)
        throws XrootdException
    {
        try {
            closeOpenFile(msg.getFileHandle());
            return withOk(msg);
        } catch (IOException e) {
            throw new XrootdException(kXR_IOError, e.getMessage());
        }
    }

    private int addOpenFile(RandomAccessFile raf)
    {
       for (int i = 0; i < _openFiles.size(); i++) {
           if (_openFiles.get(i) == null) {
               _openFiles.set(i, raf);
               return i;
           }
       }

       _openFiles.add(raf);
       return _openFiles.size() - 1;
    }

    private RandomAccessFile getOpenFile(int fd)
        throws XrootdException
    {
        if (fd >= 0 && fd < _openFiles.size()) {
            RandomAccessFile raf = _openFiles.get(fd);
            if (raf != null) {
                return raf;
            }
        }
        throw new XrootdException(kXR_FileNotOpen, "Invalid file descriptor");
    }

    private void closeOpenFile(int fd)
        throws XrootdException, IOException
    {
        getOpenFile(fd).close();
        _openFiles.set(fd, null);
    }

    private File getFile(String path)
        throws XrootdException
    {
        String normalized = FilenameUtils.normalize(path);
        if (normalized == null) {
            throw new XrootdException(kXR_ArgInvalid, "Invalid path: " + path);
        }
        return new File(_configuration.root, normalized);
    }

    private int getFileStatusFlagsOf(File file)
    {
        int flags = 0;
        if (file.isDirectory()) {
            flags |= kXR_isDir;
        }
        if (!file.isFile() && !file.isDirectory()) {
            flags |= kXR_other;
        }
        if (file.canExecute()) {
            flags |= kXR_xset;
        }
        if (file.canRead()) {
            flags |= kXR_readable;
        }
        if (file.canWrite()) {
            flags |= kXR_writable;
        }
        return flags;
    }

    private FileStatus getFileStatusOf(File file)
    {
        int flags = getFileStatusFlagsOf(file);
        return new FileStatus(0,
                              file.length(),
                              flags,
                              file.lastModified() / 1000);
    }
}