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
package org.dcache.xrootd.security;

import org.junit.Test;

import org.dcache.xrootd.core.XrootdException;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.*;

public class SecurityInfoTest
{
    @Test(expected=XrootdException.class)
    public void shouldThrowExceptionIfNameMissing() throws Exception
    {
        new SecurityInfo("");
    }

    @Test
    public void shouldAcceptOnlyName() throws Exception
    {
        SecurityInfo info = new SecurityInfo("name");

        assertThat(info.toString(), is(equalTo("name")));
        assertThat(info.getProtocol(), is(equalTo("name")));
        assertThat(info.getValue("key").isPresent(), is(equalTo(false)));
    }

    @Test
    public void shouldAcceptOnlyNameWithComma() throws Exception
    {
        SecurityInfo info = new SecurityInfo("name,");

        assertThat(info.toString(), is(equalTo("name,")));
        assertThat(info.getProtocol(), is(equalTo("name")));
        assertThat(info.getValue("key").isPresent(), is(equalTo(false)));
    }

    @Test
    public void shouldAcceptOnlyNameWithValue() throws Exception
    {
        SecurityInfo info = new SecurityInfo("name,key:value");

        assertThat(info.toString(), is(equalTo("name,key:value")));
        assertThat(info.getProtocol(), is(equalTo("name")));
        assertThat(info.getValue("key").get(), is(equalTo("value")));
    }

    @Test
    public void shouldReturnValueIfRequiredValuePresent() throws Exception
    {
        SecurityInfo info = new SecurityInfo("name,foo:value");

        assertThat(info.getRequiredValue("foo"), is(equalTo("value")));
    }

    @Test(expected=XrootdException.class)
    public void shouldThrowExceptionIfRequiredValueMissing() throws Exception
    {
        SecurityInfo info = new SecurityInfo("name,foo:value");

        assertThat(info.getRequiredValue("bar"), is(equalTo("value")));
    }
}
