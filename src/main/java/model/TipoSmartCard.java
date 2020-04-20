package model;

/**
 * Lista dos tipos de smart cards disponíveis.
 *
 * @author Thiago Acórdi Ramos - 14/07/2015.
 * @since 1.1.0
 */
public enum TipoSmartCard {

	/**
	 * Smart card do tipo Windows (acesso via repositório Windows-MY).
	 */
	WINDOWS,
	/**
	 * Smart card do tipo PKCS#12 (arquivo).
	 */
	PKCS12,
        
        /**
	 * Smart card do tipo PKCS#11 (linux).
	 */
	PKCS11
}