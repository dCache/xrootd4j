/**
 * Copyright (C) 2011-2021 dCache.org <support@dcache.org>
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
package org.dcache.xrootd.protocol.messages;

import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_mkdir;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_mkdirpath;

import io.netty.buffer.ByteBuf;

/**
 * FIXME the mode field is currently unsupported, because the owner of the file
 * can not be determined. Supporting the mode is dependant on implementation of
 * authenticated (GSI) xrootd
 */
public class MkDirRequest extends PathRequest {

    private final short options;
    private final int mode;

    public MkDirRequest(ByteBuf buffer) {
        super(buffer, kXR_mkdir);

        options = buffer.getByte(4);
        mode = buffer.getUnsignedShort(18);
    }

    public short getOptions() {
        return options;
    }

    /*
      According to the xrootd protocol spec http://xrootd.org/doc/dev45/XRdv310.htm#_Toc464248821,
      kXR_mkdir and kXR_open operations  both accept kXR_mkpath as one of these flags
      that affect the behaviour of these commands.
      Nonethenless kXR_mkdir does not accept kXR_mkpath in options field
      https://github.com/xrootd/xrootd/issues/815.
      This is wrong as the xrootd code uses bit-0 in kXR_mkdir options to indicate parent directory
      elements should be created, whereas kXR_open uses bit-8 for the same behaviour.
      Therefore, the flags cannot be described using the same constant (kXR_mkpath).
      This is the reason  why dCache could not support kXR_mkpath option.

      This  is modified  to use kXR_mkdirpath one of  mkdir oprtions instead  of kXR_mkpath.
      Note that is is temporal workaround. And code should be changed once the issue is fixed.
    */
    public boolean shouldMkPath() {
        return (getOptions() & kXR_mkdirpath) == kXR_mkdirpath;
    }

    public int getMode() {
        return mode;
    }

    @Override
    public String toString() {
        return "mkdir[" + getPath() + "," + getOpaque() + "]";
    }
}
