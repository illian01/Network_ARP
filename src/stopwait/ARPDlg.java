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

	Container contentPane;

	JTextArea ARPCacheTextArea;
	JTextArea ProxyARPTextArea;
	JTextArea dstMACAddress;
	
	JLabel lblNIC;
	JLabel lblsrc;
	JLabel lbldst;

	JButton Setting_Button;
	JButton ARPCacheItemDeleteButton;
	JButton ARPCacheAllDeleteButton;
	JButton ARPCacheSendButton;
	JButton ProxyARPAddButton;
	JButton ProxyARPDeleteButton;
	JButton GratuitousARPSendButton;
	JButton TerminateButton;
	JButton CancelButton;

	static JComboBox<String> NICComboBox;

	int adapterNumber = 0;

	String Text;

	public static void main(String[] args) throws SocketException {
		// TODO Auto-generated method stub
		m_LayerMgr.AddLayer(new NILayer("NI"));
		m_LayerMgr.AddLayer(new EthernetLayer("Eth"));
		m_LayerMgr.AddLayer(new ChatAppLayer("App"));
		m_LayerMgr.AddLayer(new ARPDlg("GUI"));
		m_LayerMgr.ConnectLayers(" NI ( *Eth ( *App  ( *GUI ) ) )");
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
		
		JLabel ARPCacheIPAddressLabel = new JLabel("IP주소");
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
		
		JLabel GratuitousARPHWAddressLabel = new JLabel("HW주소");
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
		TerminateButton = new JButton("종료");
		TerminateButton.setBounds(305, 355, 100, 30);
		TerminateButton.addActionListener(new setAddressListener());
		contentPane.add(TerminateButton);
		
		CancelButton = new JButton("취소");
		CancelButton.setBounds(420, 355, 100, 30);
		CancelButton.addActionListener(new setAddressListener());
		contentPane.add(CancelButton);
		
		setVisible(true);
	}

	class setAddressListener implements ActionListener {
		@Override
		public void actionPerformed(ActionEvent e) {
			if (e.getSource() == NICComboBox) {
				ProxyARPTextArea.setText("");
				NILayer NI = (NILayer) m_LayerMgr.GetLayer("NI");
				List<PcapIf> l = NI.m_pAdapterList;
				try {
					byte[] address = l.get(NICComboBox.getSelectedIndex()).getHardwareAddress();
					int j = 0;
					for (byte inetAddress : address) {
						ProxyARPTextArea.append(String.format("%02x", inetAddress));
						if (j++ != address.length - 1)
							ProxyARPTextArea.append("-");
					}
				} catch (IOException e1) {
					e1.printStackTrace();
				}
			} else if (e.getSource() == Setting_Button) {
				if (Setting_Button.getText().equals("Setting")) {
					
					if (dstMACAddress.getText().equals("") || ProxyARPTextArea.getText().equals("")) {
						JOptionPane.showMessageDialog(null, "입력이 없습니다!");
					}
					else {
						NILayer NI = (NILayer) m_LayerMgr.GetLayer("NI");
						EthernetLayer Eth = (EthernetLayer) m_LayerMgr.GetLayer("Eth");

						Eth.Setenet_dstaddr(dstMACAddress.getText());
						Eth.Setenet_srcaddr(ProxyARPTextArea.getText());
						int i = NICComboBox.getSelectedIndex();
						NI.SetAdapterNumber(i);

						dstMACAddress.setEnabled(false);
						ProxyARPTextArea.setEnabled(false);
						NICComboBox.setEnabled(false);
						Setting_Button.setText("Reset");
					}
				} else {
					dstMACAddress.setEnabled(true);
					ProxyARPTextArea.setEnabled(true);
					NICComboBox.setEnabled(true);
					dstMACAddress.setText("");
					Setting_Button.setText("Setting");
				}
			} else if (e.getSource() == ARPCacheItemDeleteButton) {
				if (Setting_Button.getText().equals("Setting")) {
					JOptionPane.showMessageDialog(null, "주소 설정을 먼저 하십시오.");					
				}
				else {
					byte[] input = ARPCacheInputField.getText().getBytes();
					ARPCacheTextArea.append("[SEND]:" + ARPCacheInputField.getText() + "\n");
					p_UnderLayer.Send(input, input.length);
					ARPCacheInputField.setText("");
				}
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
