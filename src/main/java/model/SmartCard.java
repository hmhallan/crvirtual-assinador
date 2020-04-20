package model;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;

/**
 * API de acesso à smart cards.
 * <p>
 * Deve-se obter a instância a partir do método
 * {@link #getInstance(TipoSmartCard)}, fornecendo o {@link TipoSmartCard}
 * desejado.
 *
 */
public abstract class SmartCard {
	
	public static final String WINDOWS = "win";
	public static final String OS_X = "mac";
	public static final String LINUX = "lin";

	/**
	 * Referência ao keystore interno.
	 */
	protected KeyStore keyStore;
	
	
	public abstract boolean precisaAutenticacaoAoInicializar();

	/**
	 * Retorna a instância do smart card para o tipo solicitado.
	 *
	 * @param tipo
	 *            {@link TipoSmartCard}
	 * @return
	 * @throws KeyStoreException
	 *             Caso o tipo de smart card solicitado não for suportado.
	 */
	public static SmartCard getInstance(TipoSmartCard tipo) throws KeyStoreException {
		switch (tipo) {
		case WINDOWS:
			return new SmartCardWindows();
		case PKCS12:
			return new SmartCardPkcs12();
                case PKCS11:
			return new SmartCardPkcs11();
		default:
			throw new KeyStoreException("Tipo de smart card não suportado: " + tipo);
		}
	}
	
	public static SmartCard getInstance(String os) throws KeyStoreException {
		switch (os) {
		case WINDOWS:
			return new SmartCardWindows();
		case LINUX:
			return new SmartCardPkcs11();
		default:
			throw new KeyStoreException("Tipo de OS não suportado: " + os);
		}
	}

	/**
	 * Inicializa o smart card.
	 * <p>
	 * É necessário chamar este método antes de chamar qualquer outro método da
	 * API.
	 *
	 * @throws KeyStoreException
	 *             Caso o smart card não esteja inserido na leitora ou a senha
	 *             não tenha sido fornecida.
	 * @throws NoSuchAlgorithmException
	 *             Caso não seja possível obter a chave privada (ex: senha
	 *             errada).
	 * @throws CertificateException
	 *             Caso algum certificado do smart card não possa ser carregado.
	 * @throws IOException
	 *             Caso ocorra um erro de leitura do smart card ou a senha seja
	 *             necessária mas não tenha sido informada.
	 */
	public abstract void inicializar() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException;

	/**
	 * Inicializa o smart card.
	 * <p>
	 * É necessário chamar este método antes de chamar qualquer outro método da
	 * API.
	 *
	 * @param arquivo
	 *            {@link InputStream} arquivo que contém o repositório de
	 *            chaves.
	 * @param senha
	 *            {@link String} senha para inicialização do smart card.
	 * @throws KeyStoreException
	 *             Caso o smart card não esteja inserido na leitora ou a senha
	 *             não tenha sido fornecida.
	 * @throws NoSuchAlgorithmException
	 *             Caso não seja possível obter a chave privada (ex: senha
	 *             errada).
	 * @throws CertificateException
	 *             Caso algum certificado do smart card não possa ser carregado.
	 * @throws IOException
	 *             Caso ocorra um erro de leitura do smart card ou a senha seja
	 *             necessária mas não tenha sido informada.
	 * @since 1.1.0
	 */
	public abstract void inicializar(InputStream arquivo, String senha) throws KeyStoreException, NoSuchAlgorithmException,
	CertificateException, IOException;
        
        /**
	 * Inicializa o smart card.
	 * <p>
	 * É necessário chamar este método antes de chamar qualquer outro método da
	 * API.
	 *
	 * @param senha
	 *            {@link String} senha para inicialização do smart card.
	 * @throws KeyStoreException
	 *             Caso o smart card não esteja inserido na leitora ou a senha
	 *             não tenha sido fornecida.
	 * @throws NoSuchAlgorithmException
	 *             Caso não seja possível obter a chave privada (ex: senha
	 *             errada).
	 * @throws CertificateException
	 *             Caso algum certificado do smart card não possa ser carregado.
	 * @throws IOException
	 *             Caso ocorra um erro de leitura do smart card ou a senha seja
	 *             necessária mas não tenha sido informada.
	 * @since 1.1.0
	 */
	public abstract void inicializar(String senha) throws KeyStoreException, NoSuchAlgorithmException,
	CertificateException, IOException;

	/**
	 * Retorna um {@link Enumeration} dos aliases contidos no smart card.
	 * <p>
	 * Alias é o nome amigável que referencia certificados e chaves.
	 *
	 * @return {@link Enumeration} enumeração dos aliases do smart card.
	 * @throws KeyStoreException
	 *             Caso o smart card não tenha sido inicializado (ver
	 *             {@link #inicializar()}).
	 */
	public Enumeration<String> getAliases() throws KeyStoreException {
		return this.keyStore.aliases();
	}

	/**
	 * Retorna o certificado associado ao alias informado.
	 * <p>
	 * O certificado digital contém informações sobre o usuário.
	 *
	 * @param alias
	 *            {@link String} alias para o qual o certificado deve ser
	 *            buscado (ver {@link #getAliases()}).
	 * @return {@link Certificate} certificado para o alias informado ou
	 *         <code>null</code> caso não exista um certificado para o alias
	 *         informado.
	 * @throws KeyStoreException
	 *             Caso o smart card não tenha sido inicializado (ver
	 *             {@link #inicializar()}).
	 */
	public Certificate getCertificado(String alias) throws KeyStoreException {
		return this.keyStore.getCertificate(alias);
	}

	/**
	 * Retorna a cadeia de certificação para o alias informado.
	 * <p>
	 * A cadeia de certificação é utilizada para verificar a confiança e a
	 * validade de um certificado.
	 *
	 * @param alias
	 *            {@link String} alias para o qual a cadeia de certificados deve
	 *            ser buscada (ver {@link #getAliases()}).
	 * @return {@link List} lista de certificados da cadeia para o alias
	 *         informado ou <code>null</code> caso não exista uma cadeia para o
	 *         alias informado.
	 * @throws KeyStoreException
	 *             Caso o smart card não tenha sido inicializado (ver
	 *             {@link #inicializar()}).
	 */
	public List<Certificate> getCadeia(String alias) throws KeyStoreException {
		Certificate[] chain = this.keyStore.getCertificateChain(alias);
		return (chain == null ? null : Arrays.asList(chain));
	}

	/**
	 * Retorna a chave privada para o alias informado.
	 * <p>
	 * A chave privada é utilizada para assinatura de documentos e autenticação
	 * em sistemas.
	 *
	 * @param alias
	 *            {@link String} alias para o qual a chave privada deve ser
	 *            buscada (ver {@link #getAliases()}).
	 * @return {@link PrivateKey} chave privada para o alias informado ou
	 *         <code>null</code> caso não exista uma chave privada para o alias
	 *         informado.
	 * @throws UnrecoverableKeyException
	 *             Caso não seja possível obter a chave privada (ex: senha
	 *             errada).
	 * @throws KeyStoreException
	 *             Caso o smart card não tenha sido inicializado (ver
	 *             {@link #inicializar()}).
	 * @throws NoSuchAlgorithmException
	 *             Caso o algoritmo para obter a chave não seja encontrado.
	 */
	public abstract PrivateKey getChavePrivada(String alias) throws UnrecoverableKeyException, KeyStoreException,
	NoSuchAlgorithmException;
}