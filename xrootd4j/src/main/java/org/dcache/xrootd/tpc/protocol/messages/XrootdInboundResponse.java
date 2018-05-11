/**
 * Copyright (C) 2011-2016 dCache.org <support@dcache.org>
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
package org.dcache.xrootd.tpc.protocol.messages;

/**
 *  <p>Supports incoming third-party source server reponses.</p>
 *
 *  <p>StreamId and Status are standard header parts.  The Request id
 *     is added to the object to facilitate the maintenance of state. </p>
 */
public interface XrootdInboundResponse
{
    /**
     * The xrootd stream identifier (client generated).
     */
    int getStreamId();

    /**
     * The xrootd response status code.
     */
    int getStatus();

    /**
     * The xrootd request type this is a response to
     */
    int getRequestId();
}
