package util;

import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.text.ParseException;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
 
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUTCTime;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.SignerIdentifier;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;

import model.Atributos;
 
 
/**
 * Métodos utilitários para geração e manipulação de objetos ASN.1.
 * 
 */
public class UtilsAsn1 {
 
	/**
	 * Gera a estrutura <i>certificates</i> com os certificados informados para
	 * inclusão na estrutura da assinatura.
	 * <p>
	 * O certificado autoassinado (raiz) não é incluído no retorno.
	 * <p>
	 * O certificado do signatário é adicionado se não estiver na cadeia.
	 * 
	 * @param signatario
	 *            {@link Certificate} certificado do signatário.
	 * @param cadeiaSignatario
	 *            {@link List} cadeia de certificação do signatário.
	 * @return {@link ASN1Set} conjunto contendo os certificados para a
	 *         estrutura da assinatura.
	 * @throws CertificateEncodingException
	 *             Em caso de erros ao codificar o certificado.
	 * @throws IOException
	 *             Em caso de erros ao analisar a estrutura do certificado.
	 */
	public static ASN1Set gerarCertificates(Certificate signatario, List<Certificate> cadeiaSignatario)
			throws CertificateEncodingException, IOException {
 
		ASN1EncodableVector vetorCertificados = new ASN1EncodableVector();
		boolean certificadoSignatarioIncluso = false;
		for (Certificate c : cadeiaSignatario) {
			X509CertificateHolder cert = new X509CertificateHolder(c.getEncoded());
 
			// verifica se contém o certificado do signatário
			if (c.equals(signatario)) {
				certificadoSignatarioIncluso = true;
			}
 
			// Adiciona o certificado exceto se autoassinado (raiz)
			if (!cert.getIssuer().equals(cert.getSubject())) {
				vetorCertificados.add(cert.toASN1Structure());
			}
		}
 
		// Adiciona o certificado do signatário caso o mesmo não esteja na
		// cadeia
		if (!certificadoSignatarioIncluso) {
			vetorCertificados.add(new X509CertificateHolder(signatario.getEncoded()).toASN1Structure());
		}
		return new DERSet(vetorCertificados);
	}
 
	/**
	 * Gera a estrutura <i>SignerInfo</i> a partir dos dados informados.
	 * 
	 * @param atributos
	 *            {@link Atributos} atributos gerados e assinados pelo
	 *            signatário.
	 * @param certHolder
	 *            {@link X509CertificateHolder} certificado do signatário.
	 * @param suiteAssinatura
	 *            {@link SuiteAssinatura} suíte de assinatura.
	 * @param protocolizar
	 *            <code>true</code> caso a assinatura deva ser protocolizada
	 *            (carimbo do tempo) ou <code>false</code> caso contrário.
	 * @return {@link SignerInfo} estrutura <i>SignerInfo</i> contendo os dados
	 *         informados.
	 * @throws Exception
	 *             Em caso de erro na leitura dos atributos ou na protocolização
	 *             da assinatura.
	 */
	public static SignerInfo gerarSignerInfo(Atributos atributos, X509CertificateHolder certHolder, String algoritmoAssinatura) throws Exception {
 
		// Identificador do algoritmo de assinatura
		AlgorithmIdentifier digEncryptionAlgorithm = new DefaultSignatureAlgorithmIdentifierFinder().find(algoritmoAssinatura);
 
		// Identificador do algoritmo de hash
		AlgorithmIdentifier digAlgorithm = new DefaultDigestAlgorithmIdentifierFinder().find(digEncryptionAlgorithm);
 
		// Atributos da asssinatura
		ASN1Set atributosAssinados = ASN1Set.getInstance(atributos.getAtributosGerados());
		
		
		// Cria o atributo de carimbo do tempo de assinatura
//		ASN1Sequence timeStampResp = ASN1Sequence.getInstance(String.valueOf(new Date().getTime()).getBytes());
//		ASN1Sequence timeStampToken = ASN1Sequence.getInstance(timeStampResp.getObjectAt(1));
//		Attribute signatureTimeStampToken = new Attribute(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken, new DERSet(timeStampToken));
//		ASN1Set atributosNaoAssinados = new DERSet(signatureTimeStampToken);
		ASN1Set atributosNaoAssinados = null;
 
		// Identificação do signatário
		SignerIdentifier sid = new SignerIdentifier( new IssuerAndSerialNumber(certHolder.toASN1Structure()));
 
		// Informações do signatário e assinatura
		return new SignerInfo(sid, digAlgorithm, atributosAssinados, digEncryptionAlgorithm, new DEROctetString(atributos
				.getAtributosAssinados()), atributosNaoAssinados);
	}
 
 
	/**
	 * Adiciona o objeto ASN.1 ao conjunto informado.
	 * 
	 * @param objeto
	 *            {@link ASN1Encodable} objeto ASN.1 para adição.
	 * @param set
	 *            {@link ASN1Set} conjunto de objetos.
	 * @param verificarDuplicidade
	 *            <code>true</code> somente adiciona o objeto caso não exista
	 *            nenhum igual no conjunto ou <code>false</code> adiciona o
	 *            objeto sem verificar a duplicidade.
	 * @return {@link ASN1Set} conjunto contendo o objeto ASN.1 informado.
	 */
	public static ASN1Set adicionarObjeto(ASN1Encodable objeto, ASN1Set set, boolean verificarDuplicidade) {
		// Obtém os objetos do conjunto e adiciona ao vetor
		ASN1EncodableVector vetor = new ASN1EncodableVector();
		Enumeration<?> enumeration = set.getObjects();
 
		boolean hasObjeto = false;
		while (enumeration.hasMoreElements()) {
			ASN1Encodable objetoASN1 = (ASN1Encodable) enumeration.nextElement();
			vetor.add(objetoASN1);
 
			// Verifica se já existe o objeto
			if (verificarDuplicidade && objetoASN1.equals(objeto)) {
				hasObjeto = true;
			}
		}
 
		// Adiciona o novo objeto ao vetor
		if (!hasObjeto) {
			vetor.add(objeto);
		}
 
		// Retorna o novo conjunto de objetos
		return new DERSet(vetor);
	}
 
	/**
	 * Retorna o atributo identificado pelo OID da tabela de atributos
	 * informada.
	 * 
	 * @param atributos
	 *            {@link AttributeTable} tabela de atributos.
	 * @param oid
	 *            {@link DERObjectIdentifier} OID do atributo.
	 * @return {@link Attribute} atributo com o OID informado na tabela de
	 *         atributos ou <code>null</code> caso a tabela de atributos seja
	 *         nula ou o atributo não exista na tabela.
	 */
	public static Attribute getAtributo(AttributeTable atributos, ASN1ObjectIdentifier oid) {
		return (atributos != null) ? atributos.get(oid) : null;
	}
 
	/**
	 * Extrai a data de assiantura do atributo <i>timeStampToken</i>.
	 * <p>
	 * O atributo deve ser obtido da tabela de atributos não assinados da
	 * assinatura.
	 * 
	 * @param atributoCarimbo
	 *            {@link Attribute} atributo de carimbo do tempo
	 *            (<i>timeStampToken</i>).
	 * @return {@link Date} data de assinatura.
	 * @throws TSPException
	 *             Em caso de erro ao instanciar o carimbo do tempo.
	 * @throws IOException
	 *             Em caso de erro de leitura dos atributos.
	 * @throws CMSException
	 *             Em caso de erro ao instanciar a estrutura <i>signedData</i>
	 *             do carimbo do tempo.
	 */
	public static Date extrairDataTimeStampToken(Attribute atributoCarimbo) throws TSPException, IOException, CMSException {
		DERSequence sequenceAttribute = (DERSequence) atributoCarimbo.getAttrValues().getObjectAt(0);
		ContentInfo contentInfo = ContentInfo.getInstance(sequenceAttribute);
 
		// Obtém a data do carimbo do tempo
		TimeStampToken token = new TimeStampToken(new CMSSignedData(contentInfo));
		return token.getTimeStampInfo().getGenTime();
	}
 
	/**
	 * Extrai a data de assinatura do atributo <i>signingTime</i>.
	 * <p>
	 * O atributo deve ser obtido da tabela de atributos assinados da
	 * assinatura.
	 * 
	 * @param signingTime
	 *            {@link Attribute} atributo assinado <i>signingTime</i>.
	 * @return {@link Date} data de assinatura.
	 * @throws ParseException
	 *             Em caso de erros no parsing da data de assinatura.
	 */
//	public static Date extrairDataSigningTime(Attribute signingTime) throws ParseException {
//		DEREncodable time = signingTime.getAttrValues().getObjectAt(0);
//		if (time instanceof DERUTCTime) {
//			// UTCTime
//			return ((DERUTCTime) time).getAdjustedDate();
//		}
// 
//		// GeneralizedTime
//		return ((DERGeneralizedTime) time).getDate();
//	}
}