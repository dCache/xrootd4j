package org.dcache.xrootd.core;

public class XrootdException extends Exception
{
    protected final int _error;

    public XrootdException(int error, String message)
    {
        super(message);
        _error = error;
    }

    public int getError()
    {
        return _error;
    }
}