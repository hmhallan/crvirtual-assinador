package repository;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.apache.commons.lang3.exception.ExceptionUtils;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import model.Atributos;
import model.Documento;
import model.SmartCard;
import model.dto.CertificadoDTO;
import model.exception.AutenticacaoNecessariaException;
import model.exception.ErroAoAssinarException;
import model.exception.ErroAoLerSmartCardException;
import model.exception.NenhumCertificadoEncontradoException;
import model.exception.PinIncorretoException;
import util.UtilsAsn1;
import util.UtilsX509;

public class SmartCardRepository {
	
	
	public static final String OS_NAME_PROPERTY = "os.name";
	
	public static final String NOT_FOUND_ERROR_MESSAGE = "java.security.KeyStoreException: PKCS11 not found";
	public static final String PIN_INCORRECT_ERROR_MESSAGE = "PKCS11Exception: CKR_PIN_INCORRECT";
	
	private static final String ALGORITMO_ASSINATURA = "SHA1WithRSA";
	
	private SmartCard smartCard;
	
	public boolean isInicializado() {
		return this.smartCard != null;
	}
	
	public void inicializar() throws NenhumCertificadoEncontradoException, AutenticacaoNecessariaException, ErroAoLerSmartCardException, PinIncorretoException {
		this.inicializar(null);
	}
	
	public void inicializar(String pin) throws NenhumCertificadoEncontradoException, AutenticacaoNecessariaException, ErroAoLerSmartCardException, PinIncorretoException {
		try {
			SmartCard smartCard = SmartCard.getInstance(this.getOs());
			
			if (smartCard.precisaAutenticacaoAoInicializar() ) {
				if (pin == null) {
					throw new AutenticacaoNecessariaException("Informe o PIN");
				}
				smartCard.inicializar(pin);
			}
			else {
				smartCard.inicializar();
			}
			
			this.smartCard = smartCard;
			
		} catch (KeyStoreException e) {
			if ( NOT_FOUND_ERROR_MESSAGE.equals(e.getMessage()) ) {
				throw new NenhumCertificadoEncontradoException("Nenhum certificado digital encontrado", e);
			}
			else {
				System.err.println(e.getMessage());
			}
		} catch (NoSuchAlgorithmException | CertificateException cause) {
			throw new ErroAoLerSmartCardException(cause);
		} catch (IOException cause) {
			
			String message = ExceptionUtils.getRootCauseMessage(cause);
			if ( PIN_INCORRECT_ERROR_MESSAGE.equals(message) ) {
				throw new PinIncorretoException("PIN informado é incorreto");
			}
			
			throw new ErroAoLerSmartCardException(cause);
		}
	}
	
	public X509Certificate consultar(String alias) throws NenhumCertificadoEncontradoException, AutenticacaoNecessariaException, ErroAoLerSmartCardException, PinIncorretoException, KeyStoreException{
		if (this.smartCard == null) {
			this.inicializar();
		}
		return (X509Certificate)this.smartCard.getCertificado(alias);
	}
	
	public List<Certificate> consultarCadeia(String alias) throws NenhumCertificadoEncontradoException, AutenticacaoNecessariaException, ErroAoLerSmartCardException, PinIncorretoException, KeyStoreException{
		if (this.smartCard == null) {
			this.inicializar();
		}
		return this.smartCard.getCadeia(alias);
	}
	
	
	public List<CertificadoDTO> listarTodos() throws NenhumCertificadoEncontradoException, AutenticacaoNecessariaException, ErroAoLerSmartCardException, PinIncorretoException {
		
		if (this.smartCard == null) {
			this.inicializar();
		}
		
		List<CertificadoDTO> lista = new ArrayList<>();
		
		try {
			String alias = smartCard.getAliases().nextElement();
			X509Certificate certificado = (X509Certificate)smartCard.getCertificado(alias);
			
			lista.add( this.build(certificado, alias) );
			
		} catch (KeyStoreException e) {
			throw new ErroAoLerSmartCardException(e);
		}
		
		return lista;
		
	}
	
	public byte [] assinar( String alias, String pin, Documento documento ) throws ErroAoAssinarException {
		try {
			
			X509Certificate signatario = this.consultar(alias);
			List<Certificate> cadeia = this.consultarCadeia(alias);
			PrivateKey chavePrivada = this.smartCard.getChavePrivada(alias);
			
			Atributos atributos = this.gerarAtributos(documento);
			atributos.setAtributosAssinados(assinarRSA(atributos.getAtributosGerados(), chavePrivada));

		
			//Informações certificado do signatário
			X509CertificateHolder signatarioHolder = new X509CertificateHolder(signatario.getEncoded());
			
			SignerInfo signerInfo = UtilsAsn1.gerarSignerInfo(atributos, signatarioHolder, ALGORITMO_ASSINATURA);
			 
			// Conjunto dos certificados
			ASN1Set certificates = UtilsAsn1.gerarCertificates(signatario, cadeia);
			
			// Conjunto das LCRs (sempre vazio)
			ASN1Set certrevlist = null;
	 
			// Conteúdo é nulo (assinatura detached, não anexada)
			ContentInfo encInfo = new ContentInfo(CMSObjectIdentifiers.data, null);
			
			// digestAlgorithms
			ASN1Set digestAlgorithms = new DERSet(signerInfo.getDigestAlgorithm());
	 
			// Estrutura da informação assinada
			SignedData sd = new SignedData(digestAlgorithms, encInfo, certificates, certrevlist, new DERSet(signerInfo));
			ContentInfo cms = new ContentInfo(CMSObjectIdentifiers.signedData, sd);
			byte [] assinatura = cms.getEncoded();
			
			return assinatura;
			
		} catch (Exception e) {
			throw new ErroAoAssinarException(e);
		}
		
	}
	
	private Atributos gerarAtributos( Documento documento ) throws ErroAoAssinarException {
		
		try {
			// Gera tabela com os atributos da assinatura
			ASN1EncodableVector vetorAtributos = new ASN1EncodableVector();
	 
			// Atributo contentType
			Attribute attr = new Attribute(CMSAttributes.contentType, new DERSet(CMSObjectIdentifiers.data));
			vetorAtributos.add(attr);
	 
			// Atributo signingTime
			// System.out.println("time=" + new Date().getTime());
			attr = new Attribute(CMSAttributes.signingTime, new DERSet(new Time(new Date())));
			vetorAtributos.add(attr);
	 
			// Atributo messageDigest
			
			attr = new Attribute(CMSAttributes.messageDigest, new DERSet(new DEROctetString(documento.getHashMD5())));
			
			vetorAtributos.add(attr);
	 
			// Retorna os atributos assinados codificados em DER
			DERSet signedAttr = new DERSet(vetorAtributos);
			byte[] encoded = signedAttr.getEncoded(ASN1Encoding.DER);
			
			return new Atributos(encoded);
		
		} catch (NoSuchAlgorithmException | IOException e) {
			throw new ErroAoAssinarException(e);
		}
		
	}
	
	/**
	 * Assina digitalmente o dado com a chave privada do signatário informada.
	 * <p>
	 * A suíte de assinatura será obtida por meio do método
	 * {@link #getSuiteAssinatura()}.
	 * 
	 * @param dado
	 *            informação para assinar (gerada pelo método
	 *            {@link #gerarInformacaoParaAssinar(byte[], Certificate)}).
	 * @param chavePrivada
	 *            {@link PrivateKey} chave privada do signatário.
	 * @return dado assinado (cifrado) com a chave privada informada.
	 * @throws Exception
	 *             Em caso de erros ao realizar a assinatura do dado informado.
	 */
	// TODO Criar esquema de fallback com os algoritmos suportados pelo cliente.
	private static byte[] assinarRSA(byte[] dado, PrivateKey chavePrivada) throws Exception {
		Signature signature = Signature.getInstance(ALGORITMO_ASSINATURA);
		signature.initSign(chavePrivada);
		signature.update(dado);
		return signature.sign();
	}
	
	
	private CertificadoDTO build(X509Certificate certificado, String alias) {
		
		X500Principal principal  = certificado.getSubjectX500Principal();
		
		CertificadoDTO dto = new CertificadoDTO()
									.setNomeSignatario(UtilsX509.getNomeSignatario(certificado))
									.setCpf(UtilsX509.getCPF(certificado))
									.setEmail(UtilsX509.getEmail(certificado))
									.setValidade(certificado.getNotAfter())
									.setEmissao(certificado.getNotBefore())
									.setAlias(alias);
		
		
		String[] cadeia = principal.getName().split(",");
		for (String s: cadeia){
	          dto.addCadeia(s.trim());
		}
		
		return dto;
	}

	
	private String getOs() {
		String osName = System.getProperty(OS_NAME_PROPERTY).toLowerCase();
		if(osName.startsWith(SmartCard.WINDOWS)) return SmartCard.WINDOWS;
		else if(osName.startsWith(SmartCard.LINUX)) return SmartCard.LINUX;
		else if(osName.startsWith(SmartCard.OS_X)) return SmartCard.OS_X;
		return null;
	}
}
