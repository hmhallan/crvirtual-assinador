package model.dto;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class CertificadoDTO {
	
	private String alias;
	private String principal;
	
	private String cpf;
	private String email;
	private String nomeSignatario;
	
	private Date emissao;
	private Date validade;
	
	private List<String> cadeia;
	
	@Override
	public String toString() {
		return "CertificadoDTO [alias=" + alias + ", cpf=" + cpf + ", email=" + email + ", nomeSignatario="
				+ nomeSignatario + ", emissao=" + emissao + ", validade=" + validade + ", cadeia=" + cadeia + "]";
	}

	public CertificadoDTO addCadeia(String cadeia) {
		if (this.cadeia == null) {
			this.cadeia = new ArrayList<>();
		}
		this.cadeia.add(cadeia);
		return this;
	}

	public String getPrincipal() {
		return principal;
	}

	public CertificadoDTO setPrincipal(String principal) {
		this.principal = principal;
		return this;
	}

	public String getCpf() {
		return cpf;
	}

	public CertificadoDTO setCpf(String cpf) {
		this.cpf = cpf;
		return this;
	}

	public String getEmail() {
		return email;
	}

	public CertificadoDTO setEmail(String email) {
		this.email = email;
		return this;
	}

	public String getNomeSignatario() {
		return nomeSignatario;
	}

	public CertificadoDTO setNomeSignatario(String nomeSignatario) {
		this.nomeSignatario = nomeSignatario;
		return this;
	}

	public List<String> getCadeia() {
		return cadeia;
	}

	public void setCadeia(List<String> cadeia) {
		this.cadeia = cadeia;
	}

	public Date getValidade() {
		return validade;
	}

	public CertificadoDTO setValidade(Date validade) {
		this.validade = validade;
		return this;
	}

	public Date getEmissao() {
		return emissao;
	}

	public CertificadoDTO setEmissao(Date emissao) {
		this.emissao = emissao;
		return this;
	}

	public String getAlias() {
		return alias;
	}

	public CertificadoDTO setAlias(String alias) {
		this.alias = alias;
		return this;
	}
	
	

}
