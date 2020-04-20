package model.exception;

public class ErroAoLerSmartCardException extends Exception {

	private static final long serialVersionUID = 3082903504734687687L;

	public ErroAoLerSmartCardException(String message) {
		super(message);
	}
	
	public ErroAoLerSmartCardException(Throwable cause) {
		super(cause);
	}
	
	public ErroAoLerSmartCardException(String message, Throwable cause) {
		super(message, cause);
	}

}
