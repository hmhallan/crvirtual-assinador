package model;

import java.io.Serializable;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
 
public class Atributos implements Serializable {
 
	private static final long serialVersionUID = -7122538443266910493L;
	
	private final byte[] atributosGerados;
	private byte[] atributosAssinados;
 
	public Atributos(byte[] atributosGerados) {
		this.atributosGerados = atributosGerados;
	}
 
	public byte[] getAtributosGerados() {
		return this.atributosGerados;
	}
	
	public void setAtributosAssinados(byte[] atributosAssinados) {
		this.atributosAssinados = atributosAssinados;
	}
	
	public byte[] getAtributosAssinados() {
		return this.atributosAssinados;
	}
 
	public byte[] getHashAtributosAssinados(String algoritmo) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance(algoritmo);
		md.update(this.getAtributosAssinados());
		return md.digest();
	}
	
	public byte[] getHashAtributosAssinadosSHA() throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA1");
		md.update(this.getAtributosAssinados());
		return md.digest();
	}
}