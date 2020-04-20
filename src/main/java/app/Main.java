package app;

import java.awt.Desktop;
import java.awt.SystemTray;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;

import javax.swing.JOptionPane;

import model.Documento;
//import io.undertow.Undertow;
//import io.undertow.server.HttpHandler;
//import io.undertow.server.HttpServerExchange;
//import io.undertow.util.Headers;
import model.dto.CertificadoDTO;
import model.exception.AutenticacaoNecessariaException;
import model.exception.ErroAoAssinarException;
import model.exception.ErroAoLerSmartCardException;
import model.exception.NenhumCertificadoEncontradoException;
import model.exception.PinIncorretoException;
import repository.SmartCardRepository;
import view.tray.TrayIconHandler;

public class Main {
	
	public static final String HOST = "localhost";
	public static final int PORT = 5050;
	
	public static void main(final String[] args) throws Exception {
        smartCard();
    }
	
	public static void smartCard()  {
		
		String pin = null;
		
		SmartCardRepository repository = new SmartCardRepository();
		
		try {
			repository.inicializar();
		} catch ( AutenticacaoNecessariaException e) {
			pin = JOptionPane.showInputDialog("Informe o PIN");
			try {
				repository.inicializar(pin);
			} catch (Exception e1) {
				e1.printStackTrace();
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		if (repository.isInicializado()) {
			try {
			List<CertificadoDTO> lista = repository.listarTodos();
			
			lista.stream().forEach(System.out::println);
			
			CertificadoDTO certificado = lista.get(0);
			
			InputStream is = Main.class.getResourceAsStream("/images/key-icon.png");
			
			Documento documento = Documento.from(is);
			repository.assinar(certificado.getAlias(), pin, documento);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		
    }
	
	
	
	/*
	public static void containerLocal() throws Exception {
		Undertow server = Undertow.builder()
                .addHttpListener(PORT, HOST)
                .setHandler(new HttpHandler() {
                    @Override
                    public void handleRequest(final HttpServerExchange exchange) throws Exception {
                        exchange.getResponseHeaders().put(Headers.CONTENT_TYPE, "text/plain");
                        exchange.getResponseSender().send("Hello World");
                    }
                }).build();
        server.start();
        
        System.out.println("iniciou em http://" + HOST + ":" + PORT +  "/  Aperte ^C para finalizar");
        
        if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
            try {
				Desktop.getDesktop().browse(new URI("http://" + HOST + ":" + PORT));
			} catch (IOException | URISyntaxException e) {
				e.printStackTrace();
			}
        }
        
        if (SystemTray.isSupported()) {
        	new TrayIconHandler();
        }
        else {
        	System.out.println("Tray icon não suportado");
        }
	}
	*/


}
