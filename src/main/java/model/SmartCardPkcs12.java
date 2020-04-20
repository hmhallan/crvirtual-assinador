package model;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

/**
 * Implementação de smart cards de repositório do tipo PKCS#12.
 *
 * @since 1.1.0
 */
class SmartCardPkcs12 extends SmartCard {

	/**
	 * Nome do repositório PKCS#12.
	 */
	private static final String REPOSITORIO_PKCS12 = "PKCS12";

	/**
	 * Senha do PKCS#12.
	 */
	private char[] senha;

	/**
	 *
	 * @throws KeyStoreException
	 */
	protected SmartCardPkcs12() throws KeyStoreException {
		this.keyStore = KeyStore.getInstance(REPOSITORIO_PKCS12);
	}

	@Override
	public void inicializar() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		throw new KeyStoreException("Smart cards do tipo PKCS#12 devem ser inicializados informando um arquivo e senha.");
	}
        
        @Override
	public void inicializar(String senha) throws KeyStoreException, NoSuchAlgorithmException,
	CertificateException, IOException {
		throw new KeyStoreException("Smart cards do tipo PKCS#12 devem ser inicializados informando um arquivo e senha.");
	}

	@Override
	public void inicializar(InputStream arquivo, String senha) throws KeyStoreException, NoSuchAlgorithmException,
	CertificateException, IOException {

		this.senha = (senha == null ? null : senha.toCharArray());
		this.keyStore.load(arquivo, this.senha);
	}

	@Override
	public PrivateKey getChavePrivada(String alias) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
		return (PrivateKey) this.keyStore.getKey(alias, this.senha);
	}
	
	@Override
	public boolean precisaAutenticacaoAoInicializar() {
		return true;
	}
}