package model.exception;

public class PinIncorretoException extends Exception {

	private static final long serialVersionUID = 2935798883655733934L;

	public PinIncorretoException(String message) {
		super(message);
	}
	
	public PinIncorretoException(String message, Throwable cause) {
		super(message, cause);
	}

}