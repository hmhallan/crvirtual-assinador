package view.tray;

import java.awt.AWTException;
import java.awt.Image;
import java.awt.PopupMenu;
import java.awt.SystemTray;
import java.awt.Toolkit;
import java.awt.TrayIcon;

public class TrayIconHandler {
	
	SystemTray tray;
	
	public TrayIconHandler() {
		
		this.tray = SystemTray.getSystemTray();
		 
		Image image = Toolkit.getDefaultToolkit().getImage("images/key-icon.png");
		
		final PopupMenu popup = new PopupMenu();
        final TrayIcon trayIcon = new TrayIcon(image, "Assinador");
        
        trayIcon.setPopupMenu(popup);
        
        try {
            tray.add(trayIcon);
        } catch (AWTException e) {
            System.out.println("TrayIcon could not be added.");
        }
		 
	}

}
