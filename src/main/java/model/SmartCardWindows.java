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
 * Implementação de acesso à smart cards por meio do repositório do Windows.
 * <p>
 * Para acesso direto aos smart cards seria necessário configurar os drivers
 * PKCS#11 para cada tipo de smart card. Todavia, o repositório de certificados
 * do Windows provê acesso aos smart cards sem demandar tal configuração.
 * <p>
 * O repositório do Windows acessado é o <code>MY</code>.
 *
 */
class SmartCardWindows extends SmartCard {

	/**
	 * Nome do repositório do Windows MY.
	 */
	private static final String REPOSITORIO_WINDOWS = "Windows-MY";

	/**
	 * Inicializa o acesso ao smart card por meio do repositório do Windows.
	 *
	 * @throws KeyStoreException
	 *             Caso não exista suporte para acesso ao repositório.
	 */
	protected SmartCardWindows() throws KeyStoreException {
		this.keyStore = KeyStore.getInstance(REPOSITORIO_WINDOWS);
	}

	@Override
	public void inicializar() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		inicializar(null, null);
	}
        
        @Override
	public void inicializar(String senha) throws KeyStoreException, NoSuchAlgorithmException,
	CertificateException, IOException {
		if ((senha != null)) {
			throw new KeyStoreException("O arquivo e a senha devem ser nulos para smart cards do tipo Windows.");
		}
	}

	@Override
	public void inicializar(InputStream arquivo, String senha) throws KeyStoreException, NoSuchAlgorithmException,
	CertificateException, IOException {

		if ((arquivo != null) || (senha != null)) {
			throw new KeyStoreException("O arquivo e a senha devem ser nulos para smart cards do tipo Windows.");
		}

		/*
		 * Se o SecurityManager estiver instalado será requisitada a
		 * SecurityPermission "authProvider.SunMSCAPI".
		 */
		this.keyStore.load(null, null);

		String smartcardError = "Smart card não encontrado.\nInsira o Smart card.";
		try {
			if (this.keyStore.size() == 0) {
				throw new KeyStoreException(smartcardError);
			}
		} catch (KeyStoreException e) {
			throw new KeyStoreException(smartcardError, e);
		}
	}

	@Override
	public PrivateKey getChavePrivada(String alias) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
		return (PrivateKey) this.keyStore.getKey(alias, null);
	}
	
	@Override
	public boolean precisaAutenticacaoAoInicializar() {
		return false;
	}
}