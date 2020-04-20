package model.exception;

public class NenhumCertificadoEncontradoException extends Exception {

	private static final long serialVersionUID = 6649798950371307844L;
	
	
	public NenhumCertificadoEncontradoException(String message) {
		super(message);
	}
	
	public NenhumCertificadoEncontradoException(String message, Throwable cause) {
		super(message, cause);
	}

}
