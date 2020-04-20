package model.exception;

public class ErroAoAssinarException extends Exception {

	private static final long serialVersionUID = -3980713687083011239L;

	public ErroAoAssinarException(String message) {
		super(message);
	}
	
	public ErroAoAssinarException(Throwable cause) {
		super(cause);
	}
	
	public ErroAoAssinarException(String message, Throwable cause) {
		super(message, cause);
	}

}