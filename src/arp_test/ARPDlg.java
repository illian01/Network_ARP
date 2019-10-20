package arp_test;

import java.awt.Color;
import java.awt.Container;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

import javax.swing.DefaultListCellRenderer;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.UIManager;
import javax.swing.border.BevelBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapAddr;
import org.jnetpcap.PcapIf;

public class ARPDlg extends JFrame implements BaseLayer {
	public int nUpperLayerCount = 0;
	public String pLayerName = null;
	public BaseLayer p_UnderLayer = null;
	public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();
	BaseLayer UnderLayer;

	private LayerManager m_LayerMgr = new LayerManager();

	private JTextField ARPCacheInputField;
	private JTextField GratuitousARPInputField;

	JComboBox<String> NICComboBox;
	
	Container contentPane;

	JList<String> ARPCacheList;
	JList<String> ProxyARPEntryList;
	
	JButton ARPCacheItemDeleteButton;
	JButton ARPCacheAllDeleteButton;
	JButton ARPCacheSendButton;
	JButton ProxyARPAddButton;
	JButton ProxyARPDeleteButton;
	JButton GratuitousARPSendButton;
	JButton SettingButton;
	JButton ExitButton;

	public ARPDlg(String pName, LayerManager m_LayerMgr) throws SocketException {
		pLayerName = pName;
		this.m_LayerMgr = m_LayerMgr;
		// TestARP window 
		setTitle("TestARP");
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setBounds(250, 250, 837, 450);
		contentPane = new JPanel();
		((JComponent) contentPane).setBorder(new EmptyBorder(5, 5, 5, 5));
		setContentPane(contentPane);
		contentPane.setLayout(null);

		// ARP Cache part
		JPanel ARPCachePanel = new JPanel();
		ARPCachePanel.setBorder(new TitledBorder(UIManager.getBorder("TitledBorder.border"), "ARP Cache",
				TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		ARPCachePanel.setBounds(10, 5, 400, 340);
		contentPane.add(ARPCachePanel);
		ARPCachePanel.setLayout(null);

		ARPCacheList = new JList<String>();
		ARPCacheList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		ARPCacheList.setBounds(10, 20, 380, 210);
		
		JScrollPane ARPCachescrollPane = new JScrollPane(ARPCacheList);
		ARPCachescrollPane.setBounds(10, 20, 380, 210);
		ARPCachePanel.add(ARPCachescrollPane);

		ARPCacheItemDeleteButton = new JButton("Item Delete");
		ARPCacheItemDeleteButton.setBounds(40, 240, 150, 40);
		ARPCacheItemDeleteButton.addActionListener(new setAddressListener());
		ARPCachePanel.add(ARPCacheItemDeleteButton);// chatting send button
		
		ARPCacheAllDeleteButton = new JButton("All Delete");
		ARPCacheAllDeleteButton.setBounds(210, 240, 150, 40);
		ARPCacheAllDeleteButton.addActionListener(new setAddressListener());
		ARPCachePanel.add(ARPCacheAllDeleteButton);
		
		JLabel ARPCacheIPAddressLabel = new JLabel("IP Address");
		ARPCacheIPAddressLabel.setBounds(10, 290, 70, 30);
		ARPCachePanel.add(ARPCacheIPAddressLabel);
		
		ARPCacheInputField = new JTextField();
		ARPCacheInputField.setBounds(85, 290, 230, 30);
		ARPCacheInputField.setHorizontalAlignment(JTextField.CENTER);
		ARPCachePanel.add(ARPCacheInputField);
		
		ARPCacheSendButton = new JButton("Send");
		ARPCacheSendButton.setBounds(320, 290, 70, 30);
		ARPCacheSendButton.addActionListener(new setAddressListener());
		ARPCachePanel.add(ARPCacheSendButton);
		
		// Proxy ARP Entry part
		JPanel ProxyARPEntryPanel = new JPanel();
		ProxyARPEntryPanel.setBorder(new TitledBorder(UIManager.getBorder("TitledBorder.border"), "Proxy ARP Entry",
				TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		ProxyARPEntryPanel.setBounds(415, 5, 400, 250);
		contentPane.add(ProxyARPEntryPanel);
		ProxyARPEntryPanel.setLayout(null);
		
		ProxyARPEntryList = new JList<String>();
		ProxyARPEntryList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		ProxyARPEntryList.setBounds(10, 20, 380, 170);
		
		JScrollPane ProxyARPEntryscrollPane = new JScrollPane(ProxyARPEntryList);
		ProxyARPEntryscrollPane.setBounds(10, 20, 380, 170);
		ProxyARPEntryPanel.add(ProxyARPEntryscrollPane);


		ProxyARPAddButton = new JButton("Add");
		ProxyARPAddButton.setBounds(40, 200, 150, 40);
		ProxyARPAddButton.addActionListener(new setAddressListener());
		ProxyARPEntryPanel.add(ProxyARPAddButton);// chatting send button
		
		ProxyARPDeleteButton = new JButton("Delete");
		ProxyARPDeleteButton.setBounds(210, 200, 150, 40);
		ProxyARPDeleteButton.addActionListener(new setAddressListener());
		ProxyARPEntryPanel.add(ProxyARPDeleteButton);
		
		// Gratuitous ARP part
		JPanel GratuitousARPPanel = new JPanel();
		GratuitousARPPanel.setBorder(new TitledBorder(UIManager.getBorder("TitledBorder.border"), "Gratuitous ARP",
				TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		GratuitousARPPanel.setBounds(415, 270, 400, 75);
		contentPane.add(GratuitousARPPanel);
		GratuitousARPPanel.setLayout(null);
		
		JLabel GratuitousARPHWAddressLabel = new JLabel("HW Address");
		GratuitousARPHWAddressLabel.setBounds(10, 25, 75, 30);
		GratuitousARPPanel.add(GratuitousARPHWAddressLabel);
		
		GratuitousARPInputField = new JTextField();
		GratuitousARPInputField.setBounds(95, 25, 220, 30);
		GratuitousARPInputField.setHorizontalAlignment(JTextField.CENTER);
		GratuitousARPPanel.add(GratuitousARPInputField);
		
		GratuitousARPSendButton = new JButton("Send");
		GratuitousARPSendButton.setBounds(320, 25, 70, 30);
		GratuitousARPSendButton.addActionListener(new setAddressListener());
		GratuitousARPPanel.add(GratuitousARPSendButton);
		
		// quit button
		ExitButton = new JButton("Quit");
		ExitButton.setBounds(712, 355, 100, 30);
		ExitButton.addActionListener(new setAddressListener());
		contentPane.add(ExitButton);
		
		setDefaultCloseOperation(0);
		setVisible(false);
		setResizable(false);
	}


	class setAddressListener implements ActionListener {
		@Override
		public void actionPerformed(ActionEvent e) {
			
			if(e.getSource() == ARPCacheSendButton) {
				((IPLayer)m_LayerMgr.GetLayer("IP")).SetIP_dstaddr(ARPCacheInputField.getText());
				GetUnderLayer().Send(null, 0);
			}
			else if(e.getSource() == ARPCacheItemDeleteButton) {
				if(ARPCacheList.isSelectionEmpty()) return;
				ARPLayer ARP = (ARPLayer) m_LayerMgr.GetLayer("ARP");
				String str = ARPCacheList.getSelectedValue();
				String[] token = str.split(" ");
				ARP.removeCache(token[0]);			// remove item to ARPCache table 
				ARP.updateCacheTableGUI();			// Show updated ARPCache table 
			}
			else if(e.getSource() == ARPCacheAllDeleteButton) {
				ARPLayer ARP = (ARPLayer) m_LayerMgr.GetLayer("ARP");
				ARP.removeCacheAll();
			}
			else if(e.getSource() == ProxyARPAddButton) {
				new ProxyARPWindow(m_LayerMgr);
			}
			else if(e.getSource() == ProxyARPDeleteButton) {
				if(ProxyARPEntryList.isSelectionEmpty()) return;
				ARPLayer ARP = (ARPLayer) m_LayerMgr.GetLayer("ARP");
				String str = ProxyARPEntryList.getSelectedValue();
				String[] token = str.split(" ");
				ARP.removeProxyARPCache(token[0]);		// remove item to Proxy ARPCache table 
				ARP.updateProxyARPCacheTableGUI();		// Show updated Proxy ARPCache table 
			}
			else if(e.getSource() == GratuitousARPSendButton) {
				IPLayer IP = (IPLayer) m_LayerMgr.GetLayer("IP");
				EthernetLayer ETH = (EthernetLayer) m_LayerMgr.GetLayer("Eth");
				ARPLayer ARP = (ARPLayer) m_LayerMgr.GetLayer("ARP");
				ChatDlg CHAT = (ChatDlg) m_LayerMgr.GetLayer("ChatGUI");
				
				String change_mac = GratuitousARPInputField.getText();
				ETH.Setenet_srcaddr(change_mac);
				ARP.SetMAC_srcaddr(change_mac);
				IP.SetIP_dstaddr(IP.GetSrcIPAddr());
				CHAT.srcMACAddress.setText(change_mac);
				
				GetUnderLayer().Send(null, 0);
			}
			else if(e.getSource() == ExitButton) {
				setVisible(false);
			}
		}
	}

	public boolean Receive(byte[] input) {
		return true;
	}

	public void setARPCacheInputField(JTextField ARPCacheInputField) {
		this.ARPCacheInputField = ARPCacheInputField;
	}

	@Override
	public void SetUnderLayer(BaseLayer pUnderLayer) {
		// TODO Auto-generated method stub
		if (pUnderLayer == null)
			return;
		this.p_UnderLayer = pUnderLayer;
	}

	@Override
	public void SetUpperLayer(BaseLayer pUpperLayer) {
		// TODO Auto-generated method stub
		if (pUpperLayer == null)
			return;
		this.p_aUpperLayer.add(nUpperLayerCount++, pUpperLayer);
		// nUpperLayerCount++;
	}

	@Override
	public String GetLayerName() {
		// TODO Auto-generated method stub
		return pLayerName;
	}

	@Override
	public BaseLayer GetUnderLayer() {
		// TODO Auto-generated method stub
		if (p_UnderLayer == null)
			return null;
		return p_UnderLayer;
	}

	@Override
	public BaseLayer GetUpperLayer(int nindex) {
		// TODO Auto-generated method stub
		if (nindex < 0 || nindex > nUpperLayerCount || nUpperLayerCount < 0)
			return null;
		return p_aUpperLayer.get(nindex);
	}

	@Override
	public void SetUpperUnderLayer(BaseLayer pUULayer) {
		this.SetUpperLayer(pUULayer);
		pUULayer.SetUnderLayer(this);

	}

}

class ProxyARPWindow extends JFrame {
	// When 'Add' button was clicked  
	
	private static LayerManager m_LayerMgr;
	
	private JTextField IpAddrInputField;
	private JTextField MACAddrInputField;
	
	Container contentPane;

	JList<String> ARPCacheList;
	JTextArea ProxyARPTextArea;
	
	JButton OKButton;
	JButton CancelButton;

	
	public ProxyARPWindow(LayerManager LayerMgr){
		
		m_LayerMgr = LayerMgr;

		// ProxyARPWindow window 
		setTitle("Proxy ARP Entry Add");
		setBounds(200, 450, 400, 280);
		contentPane = new JPanel();
		((JComponent) contentPane).setBorder(new EmptyBorder(5, 5, 5, 5));
		setContentPane(contentPane);
		contentPane.setLayout(null);

		JLabel 	IPAddrLabel = new JLabel("IP Address");
		IPAddrLabel.setBounds(20, 70, 80, 30);
		contentPane.add(IPAddrLabel);
		
		IpAddrInputField = new JTextField();
		IpAddrInputField.setBounds(110, 70, 230, 30);
		IpAddrInputField.setHorizontalAlignment(JTextField.CENTER);
		contentPane.add(IpAddrInputField);
		
		JLabel 	MACAddrLabel = new JLabel("MAC Address");
		MACAddrLabel.setBounds(20, 120, 80, 30);
		contentPane.add(MACAddrLabel);
		
		MACAddrInputField = new JTextField();
		MACAddrInputField.setBounds(110, 120, 230, 30);
		MACAddrInputField.setHorizontalAlignment(JTextField.CENTER);
		contentPane.add(MACAddrInputField);
		
		OKButton = new JButton("OK");
		OKButton.setBounds(85, 190, 100, 30);
		OKButton.addActionListener(new setAddressListener());
		contentPane.add(OKButton);
		
		CancelButton = new JButton("Cancel");
		CancelButton.setBounds(205, 190, 100, 30);
		CancelButton.addActionListener(new setAddressListener());
		contentPane.add(CancelButton);
		
		setVisible(true);
		setResizable(false);

	}
	
	class setAddressListener implements ActionListener {

		@Override
		public void actionPerformed(ActionEvent e) {
			
			if(e.getSource() == CancelButton) {
				 dispose();
			}
			else if(e.getSource() == OKButton) {
				
				if(!IpAddrInputField.getText().equals("") && !MACAddrInputField.getText().equals("")) {
					
					String ip = IpAddrInputField.getText();
					String mac = MACAddrInputField.getText();
					
					((ARPLayer)m_LayerMgr.GetLayer("ARP")).addProxyARPCacheTable(ip, mac);
					((ARPLayer)m_LayerMgr.GetLayer("ARP")).updateProxyARPCacheTableGUI();
					
					dispose();
				
				}
			}
		}
		
	}
	
}
