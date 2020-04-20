package model;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.apache.commons.io.IOUtils;
 
public class Documento {
 
	byte[] documento;
	
	private Documento() {
	}
 
	public static Documento from(byte[] bytesDocumento) {
		Documento d = new Documento();
		d.documento = bytesDocumento;
		return d;
	}
 
	public static Documento from(InputStream streamDocumento) throws IOException {
		Documento d = new Documento();
		d.documento = IOUtils.toByteArray(streamDocumento);
		return d;
	}
	
	public static Documento from(File fileDocumento) throws IOException {
		Documento d = new Documento();
		d.documento = Files.readAllBytes(fileDocumento.toPath());
		return d;
	}
 
	public byte[] getDocumento() {
		return this.documento;
	}
 
	public byte[] getHash(String algoritmo) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance(algoritmo);
		md.update(this.getDocumento());
		return md.digest();
	}
	
	public byte[] getHashMD5() throws NoSuchAlgorithmException {
		return this.getHash("MD5");
	}
}