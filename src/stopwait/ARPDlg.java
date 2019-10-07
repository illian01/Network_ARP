package stopwait;

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

import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.UIManager;
import javax.swing.border.BevelBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;

public class ARPDlg extends JFrame implements BaseLayer {
	public int nUpperLayerCount = 0;
	public String pLayerName = null;
	public BaseLayer p_UnderLayer = null;
	public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();
	BaseLayer UnderLayer;

	private static LayerManager m_LayerMgr = new LayerManager();

	private JTextField ARPCacheInputField;
	private JTextField GratuitousARPInputField;

	JComboBox<String> NICComboBox;
	
	Container contentPane;

	JTextArea ARPCacheTextArea;
	JTextArea ProxyARPTextArea;
	
	JButton ARPCacheItemDeleteButton;
	JButton ARPCacheAllDeleteButton;
	JButton ARPCacheSendButton;
	JButton ProxyARPAddButton;
	JButton ProxyARPDeleteButton;
	JButton GratuitousARPSendButton;
	JButton SettingButton;
	JButton ExitButton;

	public static void main(String[] args) throws SocketException {
		// TODO Auto-generated method stub
		m_LayerMgr.AddLayer(new NILayer("NI"));
		m_LayerMgr.AddLayer(new EthernetLayer("Eth"));
		m_LayerMgr.AddLayer(new ARPLayer("ARP"));
		m_LayerMgr.AddLayer(new IPLayer("IP"));
		m_LayerMgr.AddLayer(new TCPLayer("TCP"));
		m_LayerMgr.AddLayer(new AppLayer("App"));
		m_LayerMgr.AddLayer(new ARPDlg("GUI"));
		m_LayerMgr.ConnectLayers(" NI ( *Eth ( *ARP +IP ( *TCP ( *App ( *GUI ) ) ) ) )");
		m_LayerMgr.GetLayer("ARP").SetUnderUpperLayer(m_LayerMgr.GetLayer("Eth"));
		m_LayerMgr.GetLayer("IP").SetUnderLayer(m_LayerMgr.GetLayer("ARP"));
	}

	public ARPDlg(String pName) throws SocketException {
		pLayerName = pName;
		
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

		ARPCacheTextArea = new JTextArea();
		ARPCacheTextArea.setEditable(false);
		ARPCacheTextArea.setBounds(10, 20, 380, 210);
		ARPCachePanel.add(ARPCacheTextArea);

		ARPCacheItemDeleteButton = new JButton("Item Delete");
		ARPCacheItemDeleteButton.setBounds(40, 240, 150, 40);
		ARPCacheItemDeleteButton.addActionListener(new setAddressListener());
		ARPCachePanel.add(ARPCacheItemDeleteButton);// chatting send button
		
		ARPCacheAllDeleteButton = new JButton("All Delete");
		ARPCacheAllDeleteButton.setBounds(210, 240, 150, 40);
		ARPCacheAllDeleteButton.addActionListener(new setAddressListener());
		ARPCachePanel.add(ARPCacheAllDeleteButton);
		
		JLabel ARPCacheIPAddressLabel = new JLabel("IP林家");
		ARPCacheIPAddressLabel.setBounds(10, 290, 40, 30);
		ARPCachePanel.add(ARPCacheIPAddressLabel);
		
		ARPCacheInputField = new JTextField();
		ARPCacheInputField.setBounds(55, 290, 260, 30);
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

		ProxyARPTextArea = new JTextArea();
		ProxyARPTextArea.setEditable(false);
		ProxyARPTextArea.setBounds(10, 20, 380, 170);
		ProxyARPEntryPanel.add(ProxyARPTextArea);// src address

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
		
		JLabel GratuitousARPHWAddressLabel = new JLabel("HW林家");
		GratuitousARPHWAddressLabel.setBounds(10, 25, 50, 30);
		GratuitousARPPanel.add(GratuitousARPHWAddressLabel);
		
		GratuitousARPInputField = new JTextField();
		GratuitousARPInputField.setBounds(60, 25, 255, 30);
		GratuitousARPPanel.add(GratuitousARPInputField);
		
		GratuitousARPSendButton = new JButton("Send");
		GratuitousARPSendButton.setBounds(320, 25, 70, 30);
		GratuitousARPSendButton.addActionListener(new setAddressListener());
		GratuitousARPPanel.add(GratuitousARPSendButton);
		
		// Two button on bottom side
		NICComboBox = new JComboBox<>();
		List<PcapIf> l = ((NILayer) m_LayerMgr.GetLayer("NI")).m_pAdapterList;
		for (int i = 0; i < l.size(); i++)
			NICComboBox.addItem(l.get(i).getDescription() + " : " + l.get(i).getName());
		NICComboBox.setBounds(10, 355, 550, 30);
		NICComboBox.addActionListener(new setAddressListener());
		contentPane.add(NICComboBox);//
		
		SettingButton = new JButton("汲沥");
		SettingButton.setBounds(570, 355, 100, 30);
		SettingButton.addActionListener(new setAddressListener());
		contentPane.add(SettingButton);
		
		ExitButton = new JButton("辆丰");
		ExitButton.setBounds(712, 355, 100, 30);
		ExitButton.addActionListener(new setAddressListener());
		contentPane.add(ExitButton);
		
		setVisible(true);
	}

	class setAddressListener implements ActionListener {
		@Override
		public void actionPerformed(ActionEvent e) {
			if(e.getSource() == ARPCacheSendButton) {
				byte[] input = ARPCacheInputField.getText().getBytes();
				GetUnderLayer().Send(input, input.length);
			}
		}
	}

	public boolean Receive(byte[] input) {
		ARPCacheTextArea.append("[RECV]:");
		try {
			ARPCacheTextArea.append(new String(input, "MS949"));
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		ARPCacheTextArea.append("\n");

		return true;
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
