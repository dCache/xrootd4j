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

import java.util.EnumSet;
import java.util.Set;

import static java.util.stream.Collectors.toSet;

/**
 *  Indicates the reason why the client has included the 'tried' CGI list
 *  on the path URL.
 */
public enum TriedRc {
    ENOENT("enoent", "The file was not found at the listed hosts."),
    IOERR("ioerr", "The client received an I/O error on the listed hosts."),
    FSERR("fserr", "The client received a non-I/O error from the file system."),
    SRVERR("srverr", "The client received a server-related error."),
    RESEL("resel", "The client is trying to find a better server."),
    RESEG("reseg", "The client is globally trying to find a better server.");

    private static final Set<String> KEYS = EnumSet.allOf(TriedRc.class)
                                                   .stream()
                                                   .map(TriedRc::key)
                                                   .collect(toSet());

    static Set<String> keys() {
        return KEYS;
    }
    private final        String      key;
    private final        String      description;

    TriedRc(String key, String description) {
        this.key = key;
        this.description = description;
    }

    public String description() {
        return description;
    }

    public String key() {
        return key;
    }
}
