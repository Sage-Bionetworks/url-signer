package org.sagebionetworks.url;

public class SignatureExpiredException extends Exception {

	private static final long serialVersionUID = 1L;

	public SignatureExpiredException() {
	}

	public SignatureExpiredException(String message) {
		super(message);
	}

	public SignatureExpiredException(Throwable cause) {
		super(cause);
	}

	public SignatureExpiredException(String message, Throwable cause) {
		super(message, cause);
	}

	public SignatureExpiredException(String message, Throwable cause,
			boolean enableSuppression, boolean writableStackTrace) {
		super(message, cause, enableSuppression, writableStackTrace);
	}

}
