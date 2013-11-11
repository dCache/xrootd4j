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

    private long size, modtime;
    private int flags;
    private long id;

    public FileStatus(long id, long size, int flags, long modtime)
    {
        this.id = id;
        this.size = size;
        this.flags = flags;
        this.modtime = modtime;
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
        StringBuilder info = new StringBuilder();
        info.append(id);
        info.append(" ");
        info.append(size);
        info.append(" ");
        info.append(flags);
        info.append(" ");
        info.append(modtime);
        return info.toString();
    }
}
