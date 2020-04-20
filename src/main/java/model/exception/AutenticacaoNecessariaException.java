package model.exception;

public class AutenticacaoNecessariaException extends Exception {

	private static final long serialVersionUID = 6284268042365876275L;
	
	public AutenticacaoNecessariaException(String message) {
		super(message);
	}
	
	public AutenticacaoNecessariaException(String message, Throwable cause) {
		super(message, cause);
	}

}
