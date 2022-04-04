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
package org.dcache.xrootd.util;

/**
 * This class encapsulates status information about a file.
 * It is compatible with the result of TSystem::GetPathInfo() as it is found
 * in the ROOT framework.
 */
public class FileStatus
{
    @Deprecated // Kept for compatibility with plugins
    public static final FileStatus FILE_NOT_FOUND =
            new FileStatus(-1, -1, -1, -1);

    private final long size;
    private final long modtime;
    private final int flags;
    private final long id;

    public FileStatus(long id, long size, int flags, long modtime)
    {
        this.id = id;
        this.size = size;
        this.flags = flags;
        this.modtime = modtime;
    }

    /*
     * Id, size, flags, mtime
     */
    public FileStatus(String info)
    {
        String[] parts = info.trim().split("[\\s]");
        this.id = Long.parseLong(parts[0]);
        this.size = Long.parseLong(parts[1]);
        this.flags = Integer.parseInt(parts[2]);
        this.modtime = Long.parseLong(parts[3]);
    }

    public long getSize() {
        return size;
    }

    public long getModificationTime() {
        return modtime;
    }

    public int getFlags() {
        return flags;
    }

    public long getId() {
        return id;
    }

    @Override
    public String toString()
    {
        return String.valueOf(id) + " " + size + " " + flags + " " + modtime;
    }
}
