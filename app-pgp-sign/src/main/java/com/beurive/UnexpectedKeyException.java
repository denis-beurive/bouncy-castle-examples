package com.beurive;

public class UnexpectedKeyException extends Exception {
    public UnexpectedKeyException() {
        super();
    }
    public UnexpectedKeyException(String message) {
        super(message);
    }
    public UnexpectedKeyException(String message, Throwable cause) {
        super(message, cause);
    }
    public UnexpectedKeyException(Throwable cause) {
        super(cause);
    }
}
