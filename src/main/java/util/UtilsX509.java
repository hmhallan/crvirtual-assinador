package util;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CRL;
import java.security.cert.CertPathValidator;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
 
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.util.encoders.Hex;
 
/**
 * Coleção de métodos utilitários X.509.
 *
 * @author Thiago Acórdi Ramos.
 *
 */
public class UtilsX509 {
 
	/**
	 * Verifica se a cadeia contém o certificado do signatário.
	 *
	 * @param signatario
	 *            {@link Certificate} certificado do signatário.
	 * @param cadeia
	 *            {@link List} cadeia de certificação do signatário.
	 * @return <code>true</code> caso a cadeia contenha o certificado do
	 *         signatário e <code>false</code> caso contrário.
	 */
	public static boolean hasCertificadoSignatario(Certificate signatario, List<Certificate> cadeia) {
		if (cadeia == null || cadeia.isEmpty()) {
			return false;
		}
 
		X509Certificate sig = (X509Certificate) signatario;
		for (Certificate c : cadeia) {
			X509Certificate cert = (X509Certificate) c;
 
			if (sig.getSubjectX500Principal().equals(cert.getSubjectX500Principal())) {
				return true;
			}
		}
		return false;
	}
 
	/**
	 * Retorna o CPF contido no certificado.
	 * <p>
	 * O CPF somente está disponível em certificados de pessoa física (e-CPF).
	 * <p>
	 * Caso o campo não tenha sido informado será retornado "000000000000" (11
	 * dígitos zero).
	 *
	 * @param certificado
	 *            {@link Certificate} certificado de pessoa física.
	 * @return {@link String} o CPF ou <code>null</code> caso a extensão não
	 *         exista ou ocorram erros.
	 */
	public static String getCPF(Certificate certificado) {
		String cpf = null;
		try {
			String otherName = getICPBrasilOtherName(certificado, "2.16.76.1.3.1");
			if (otherName != null && otherName.length() > 18) {
				cpf = otherName.substring(8, 19);
			}
		} catch (IOException e) {
			// Extensão não existe ou ocorreu um erro inesperado
		}
		return cpf;
	}
 
	/**
	 * Retorna o e-mail contido no certificado na extensão
	 * SubjectAlternativeName.
	 *
	 * @return {@link String} e-mail ou <code>null</code> caso a extensão não
	 *         exista, ocorram erros ou o e-mail não tenha sido informado.
	 */
	public static String getEmail(Certificate certificado) {
		try {
			ASN1Object o = getExtensao(certificado, Extension.subjectAlternativeName.getId());
			GeneralNames generalNames = GeneralNames.getInstance(o);
			GeneralName[] names = generalNames.getNames();
			for (GeneralName name : names) {
				if (name.getTagNo() == 1) {
					DERIA5String ia5String = DERIA5String.getInstance(name.getName());
					return ia5String.getString();
				}
			}
		} catch (IOException e) {
			// Extensão não existe ou ocorreu um erro inesperado
		}
		return null;
	}
 
	/**
	 * Retorna o conteúdo do campo OtherName da extensão SubjectAlternativeName
	 * para o OID informado.
	 *
	 * @param oid
	 *            {@link String} OID do campo OtherName a ser buscado.
	 * @return {@link String} conteúdo do campo OtherName ou <code>null</code>
	 *         caso a extensão não exista ou ocorram erros.
	 * @throws IOException
	 */
	public static String getICPBrasilOtherName(Certificate certificado, String oid) throws IOException {
		ASN1Object o = getExtensao(certificado, Extension.subjectAlternativeName.getId());
		GeneralNames generalNames = GeneralNames.getInstance(o);
		GeneralName[] names = generalNames.getNames();
 
		for (GeneralName name : names) {
			if (name.getTagNo() == 0) {
				// OtherName
				ASN1Sequence sequence = ASN1Sequence.getInstance(name.getName());
				ASN1ObjectIdentifier id = ASN1ObjectIdentifier.getInstance(sequence.getObjectAt(0));
 
				if (id.getId().equals(oid)) {
					ASN1TaggedObject tagged = ASN1TaggedObject.getInstance(sequence.getObjectAt(1));
					ASN1Primitive taggedObject = tagged.getObject();
					if (taggedObject instanceof ASN1OctetString) {
						ASN1OctetString octetString = ASN1OctetString.getInstance(taggedObject);
						return new String(octetString.getOctets());
					}
 
					if (taggedObject instanceof DERPrintableString) {
						DERPrintableString derString = DERPrintableString.getInstance(taggedObject);
						return derString.getString();
					}
				}
			}
		}
		return null;
	}
 
	/**
	 * Retorna um objeto ASN.1 da extensão identificada pelo OID informado.
	 *
	 * @param oid
	 *            {@link String} OID da extensão desejada.
	 * @return {@link ASN1Object} objeto ASN.1 da extensão ou <code>null</code>
	 *         caso a extensão não exista ou ocorram erros.
	 * @throws IOException
	 *             Em caso de erros ao ler os objetos ASN.1.
	 */
	private static ASN1Object getExtensao(Certificate certificado, String oid) throws IOException {
		byte[] enconded = ((X509Certificate) certificado).getExtensionValue(oid);
		if (enconded == null) {
			throw new IOException("Extensão " + oid + " não presente no certificado \'"
					+ ((X509Certificate) certificado).getSubjectX500Principal() + "\'");
		}
 
		ASN1OctetString octetString = ASN1OctetString.getInstance(ASN1ObjectIdentifier.fromByteArray(enconded));
		return ASN1ObjectIdentifier.fromByteArray(octetString.getOctets());
	}
 
	/**
	 * Retorna o nome do signatário do certificado.
	 * <p>
	 * O nome é extraído do campo CN do certificado digital.
	 *
	 * @param certificado
	 *            {@link Certificate} certificado do signatário.
	 * @return {@link String} nome do signatário do certificado digital.
	 */
	public static String getNomeSignatario(Certificate certificado) {
		String dn = ((X509Certificate) certificado).getSubjectX500Principal().getName();
		int index = dn.indexOf("CN=") + 3;
		dn = dn.substring(index);
 
		// Remove CPF e demais campos do DN
		index = dn.indexOf(":");
		if (index > 0) {
			dn = dn.substring(0, index);
		}
		return dn;
	}
 
	/**
	 * Retorna a chave de autoridade do certificado ou LCR informado.
	 *
	 * @param artefato
	 *            {@link Object} certificado ou LCR.
	 * @return {@link String} chave da autoridade codificada em hexadecimal.
	 * @throws IOException
	 *             Caso o artefato não possua a extensão
	 *             <i>authorityKeyIdentifier</i> ou não seja instância de
	 *             {@link CRL} ou {@link Certificate}.
	 */
//	public static String getChaveAutoridade(Object artefato) throws IOException {
//		// Obtém a extensão authorityKeyIdentifier do certificado ou LCR
//		byte[] authorityKeyIdentifier = ((X509Certificate) artefato).getExtensionValue(X509Extension.authorityKeyIdentifier.getId());
// 
//		// Artefato não contém a extensão authorityKeyIdentifier ou não é um
//		// certificado ou LCR
//		if (authorityKeyIdentifier == null) {
//			String objeto = "Certificado \'" + ((X509Certificate) artefato).getSubjectX500Principal() + "\'";
//			throw new IOException(objeto + " não possui a extensão authorityKeyIdentifier");
//		}
// 
//		// Decodifica a extensão authorityKeyIdentifier
//		ASN1OctetString octetString = ASN1OctetString.getInstance(ASN1Object.fromByteArray(authorityKeyIdentifier));
//		ASN1Sequence sequenceAKI = ASN1Sequence.getInstance(ASN1Object.fromByteArray(octetString.getOctets()));
//		AuthorityKeyIdentifier chaveAutoridade = new AuthorityKeyIdentifier(sequenceAKI);
//		String chave = new String(Hex.encode(chaveAutoridade.getKeyIdentifier()));
//		return chave.toUpperCase();
//	}
 
	/**
	 * Gera um certificado X.509 a partir de um array de bytes.
	 *
	 * @param certificado
	 *            bytes do certificado.
	 * @return {@link X509Certificate} certificado X.509.
	 * @throws Exception
	 *             Em caso de erros ao decodificar o certificado.
	 */
	public static X509Certificate gerarCertificado(byte[] certificado) throws Exception {
		CertificateFactory factory = CertificateFactory.getInstance("X509", "SUN");
		return (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(certificado));
	}
 
	/**
	 * Gera uma {@link X509CRL} a partir de um array de bytes.
	 *
	 * @param lcr
	 *            bytes da LCR.
	 * @return {@link X509CRL} LCR.
	 * @throws Exception
	 *             Em caso de erros ao decodificar a LCR.
	 */
	public static X509CRL gerarLCR(byte[] lcr) throws Exception {
		CertificateFactory factory = CertificateFactory.getInstance("X509", "SUN");
		return (X509CRL) factory.generateCRL(new ByteArrayInputStream(lcr));
	}
 
	/**
	 * Ordena a lista de certificados para formar a cadeia esperada pelo
	 * {@link CertPathValidator}.
	 * <p>
	 * Os certificados são ordenados da entidade final para a AC mais próxima a
	 * raiz.
	 *
	 * @param cadeia
	 *            {@link List} lista de certificados da cadeia a ser ordenada.
	 * @return {@link List} lista ordenada de certificados da cadeia.
	 */
	public static List<Certificate> ordenarCadeia(List<Certificate> cadeia) {
		List<Certificate> ordenada = new ArrayList<Certificate>(cadeia.size());
 
		// Busca a entidade final da cadeia
		X509Certificate entidade = null;
		for (int i = 0; i < cadeia.size(); i++) {
			X509Certificate c = (X509Certificate) cadeia.remove(0);
			if (c.getBasicConstraints() < 0) {
				entidade = c;
				ordenada.add(entidade);
			} else {
				cadeia.add(c);
			}
		}
 
		if (entidade == null) {
			// Retorna a cadeia informada
			return cadeia;
		}
 
		// Inicia a busca pelos emissores dos certificados
		int index = 0;
		X509Certificate emitido = entidade;
		while (!cadeia.isEmpty() && index != -1) {
			X509Certificate ac = (X509Certificate) cadeia.remove(0);
			// Verifica se é a ac que emitiu o certificado
			if (emitido.getIssuerX500Principal().equals(ac.getSubjectX500Principal())) {
				ordenada.add(ac);
				emitido = ac;
				index = 0;
			} else if (index == cadeia.size()) {
				// Devolve a lista caso não seja o certificado buscado
				index = -1;
			} else {
				// Certificado foi emitido por outra AC, retorna para a lista
				cadeia.add(cadeia.size(), ac);
				index++;
			}
		}
		return ordenada;
	}
}