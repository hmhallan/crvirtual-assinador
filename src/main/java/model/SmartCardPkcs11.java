package model;


import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Enumeration;
import java.util.Set;


/**
 * Implementação de smart cards de repositório do tipo PKCS#11.
 *
 * @since 1.1.0
 */
class SmartCardPkcs11 extends SmartCard {

	/**
	 * Nome do repositório PKCS#11.
	 */
	private static final String REPOSITORIO_PKCS11 = "PKCS11";

	/**
	 * Senha do PKCS#11.
	 */
	private char[] senha;

	/**
	 *
	 * @throws KeyStoreException
	 */
	protected SmartCardPkcs11() throws KeyStoreException {
            try {
                
                String pkcs11ID = "smartcard";
//                String libraryPath = "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so";
                
                
                String libraryPath = "/usr/lib/libeToken.so.10";
                
                String pkcs11ConfigSettings = "name = " + pkcs11ID + 
                        "\nlibrary = " + libraryPath +
                        "\nshowInfo=false" +
                        "\nslotListIndex = 0";
                
                
                byte[] pkcs11ConfigBytes = pkcs11ConfigSettings.getBytes();
                ByteArrayInputStream confStream = new ByteArrayInputStream(pkcs11ConfigBytes);
                
                Provider p = new sun.security.pkcs11.SunPKCS11(confStream);
                
                Security.addProvider(p);
                
                this.keyStore = KeyStore.getInstance(REPOSITORIO_PKCS11, p);
                
                
            } catch (Exception ex) {
                throw new KeyStoreException(ex);
            }
	}

	@Override
	public void inicializar() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		this.inicializar(null);
	}

	@Override
	public void inicializar(String senha) throws KeyStoreException, NoSuchAlgorithmException,
	CertificateException, IOException {
		this.inicializar(null, senha);
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