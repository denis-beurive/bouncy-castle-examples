package org.beurive.pgp;

public class UnexpectedDocumentException extends Exception {
    public UnexpectedDocumentException() {
        super();
    }
    public UnexpectedDocumentException(String message) {
        super(message);
    }
    public UnexpectedDocumentException(String message, Throwable cause) {
        super(message, cause);
    }
    public UnexpectedDocumentException(Throwable cause) {
        super(cause);
    }
}
