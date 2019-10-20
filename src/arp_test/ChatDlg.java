package arp_test;

import java.awt.Color;
import java.awt.Component;
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

public class ChatDlg extends JFrame implements BaseLayer {
	public int nUpperLayerCount = 0;
	public String pLayerName = null;
	public BaseLayer p_UnderLayer = null;
	public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();
	BaseLayer UnderLayer;

	private static LayerManager m_LayerMgr = new LayerManager();

	private JTextField ChattingWrite;

	Container contentPane;

	JTextArea ChattingArea;
	JTextArea srcMACAddress;
	JTextArea dstIPAddress;

	JLabel lblNIC;
	JLabel lblsrc;
	JLabel lbldst;

	JButton NIC_Setting_Button;
	JButton Chat_send_Button;
	JButton Cache_Table_Button;

	static JComboBox<String> NICComboBox;

	public static void main(String[] args) throws SocketException {
		// TODO Auto-generated method stub
		m_LayerMgr.AddLayer(new NILayer("NI"));
		m_LayerMgr.AddLayer(new EthernetLayer("Eth"));
		m_LayerMgr.AddLayer(new ARPLayer("ARP"));
		m_LayerMgr.AddLayer(new IPLayer("IP"));
		m_LayerMgr.AddLayer(new TCPLayer("TCP"));
		m_LayerMgr.AddLayer(new AppLayer("App"));
		m_LayerMgr.AddLayer(new ARPDlg("ARPGUI", m_LayerMgr));
		m_LayerMgr.AddLayer(new ChatDlg("ChatGUI"));
		m_LayerMgr.ConnectLayers(" NI ( *Eth ( *ARP +IP ( *TCP ( *App ( *ARPGUI ) ) ) ) )");
		m_LayerMgr.GetLayer("ARP").SetUnderUpperLayer(m_LayerMgr.GetLayer("Eth"));
		m_LayerMgr.GetLayer("IP").SetUnderLayer(m_LayerMgr.GetLayer("ARP"));
		m_LayerMgr.GetLayer("ChatGUI").SetUnderLayer(m_LayerMgr.GetLayer("App"));
		m_LayerMgr.GetLayer("App").SetUpperLayer(m_LayerMgr.GetLayer("ChatGUI"));
	}

	public ChatDlg(String pName) throws SocketException {
		pLayerName = pName;

		// Chat window
		setTitle("Chat");
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setBounds(250, 250, 644, 425);
		contentPane = new JPanel();
		((JComponent) contentPane).setBorder(new EmptyBorder(5, 5, 5, 5));
		setContentPane(contentPane);
		contentPane.setLayout(null);
		pLayerName = pName;

		// Chatting Panel
		JPanel chattingPanel = new JPanel();
		chattingPanel.setBorder(new TitledBorder(UIManager.getBorder("TitledBorder.border"), "chatting",
				TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		chattingPanel.setBounds(10, 5, 360, 276);
		contentPane.add(chattingPanel);
		chattingPanel.setLayout(null);

		JPanel chattingEditorPanel = new JPanel();
		chattingEditorPanel.setBounds(10, 15, 340, 210);
		chattingPanel.add(chattingEditorPanel);
		chattingEditorPanel.setLayout(null);

		ChattingArea = new JTextArea();
		ChattingArea.setEditable(false);
		ChattingArea.setBounds(0, 0, 340, 210);
		chattingEditorPanel.add(ChattingArea);

		JPanel chattingInputPanel = new JPanel();
		chattingInputPanel.setBorder(new BevelBorder(BevelBorder.LOWERED, null, null, null, null));
		chattingInputPanel.setBounds(10, 230, 250, 20);
		chattingPanel.add(chattingInputPanel);
		chattingInputPanel.setLayout(null);

		ChattingWrite = new JTextField();
		ChattingWrite.setBounds(2, 2, 250, 20);
		chattingInputPanel.add(ChattingWrite);
		ChattingWrite.setColumns(10);

		// Setting Panel
		JPanel settingPanel = new JPanel();
		settingPanel.setBorder(new TitledBorder(UIManager.getBorder("TitledBorder.border"), "setting",
				TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		settingPanel.setBounds(380, 5, 236, 371);
		contentPane.add(settingPanel);
		settingPanel.setLayout(null);

		JPanel NICPanel = new JPanel();
		NICPanel.setBorder(new BevelBorder(BevelBorder.LOWERED, null, null, null, null));
		NICPanel.setBounds(10, 46, 170, 20);
		settingPanel.add(NICPanel);
		NICPanel.setLayout(null);

		lblNIC = new JLabel("NIC");
		lblNIC.setBounds(10, 25, 170, 20);
		settingPanel.add(lblNIC);

		NICComboBox = new JComboBox<>();
		List<PcapIf> l = ((NILayer) m_LayerMgr.GetLayer("NI")).m_pAdapterList;
		for (int i = 0; i < l.size(); i++)
			NICComboBox.addItem(l.get(i).getDescription() + " : " + l.get(i).getName());

		NICComboBox.setBounds(2, 2, 550, 20);
		NICComboBox.addActionListener(new setAddressListener());
		NICPanel.add(NICComboBox);// src address

		JPanel sourceAddressPanel = new JPanel();
		sourceAddressPanel.setBorder(new BevelBorder(BevelBorder.LOWERED, null, null, null, null));
		sourceAddressPanel.setBounds(10, 96, 170, 20);
		settingPanel.add(sourceAddressPanel);
		sourceAddressPanel.setLayout(null);

		lblsrc = new JLabel("Source Mac Address");
		lblsrc.setBounds(10, 75, 170, 20);
		settingPanel.add(lblsrc);

		srcMACAddress = new JTextArea();
		srcMACAddress.setBounds(2, 2, 170, 20);
		srcMACAddress.setEnabled(false);
		sourceAddressPanel.add(srcMACAddress);

		JPanel destinationAddressPanel = new JPanel();
		destinationAddressPanel.setBorder(new BevelBorder(BevelBorder.LOWERED, null, null, null, null));
		destinationAddressPanel.setBounds(10, 212, 170, 20);
		settingPanel.add(destinationAddressPanel);
		destinationAddressPanel.setLayout(null);

		lbldst = new JLabel("Destination IP Address");
		lbldst.setBounds(10, 187, 190, 20);
		settingPanel.add(lbldst);

		dstIPAddress = new JTextArea();
		dstIPAddress.setBounds(2, 2, 170, 20);
		destinationAddressPanel.add(dstIPAddress);

		NIC_Setting_Button = new JButton("Setting");
		NIC_Setting_Button.setBounds(80, 130, 100, 20);
		NIC_Setting_Button.addActionListener(new setAddressListener());
		settingPanel.add(NIC_Setting_Button);

		Cache_Table_Button = new JButton("Cache Table");
		Cache_Table_Button.setBounds(10, 270, 170, 20);
		Cache_Table_Button.addActionListener(new setAddressListener());
		settingPanel.add(Cache_Table_Button);

		Chat_send_Button = new JButton("Send");
		Chat_send_Button.setBounds(270, 230, 80, 20);
		Chat_send_Button.addActionListener(new setAddressListener());
		chattingPanel.add(Chat_send_Button);

		setVisible(true);
		setResizable(false);
	}

	class setAddressListener implements ActionListener {
		@Override
		public void actionPerformed(ActionEvent e) {
			if (e.getSource() == Cache_Table_Button) {
				if (!(NIC_Setting_Button.getText() == "Setting"))
					((Component) m_LayerMgr.GetLayer("ARPGUI")).setVisible(true);
			} else if (e.getSource() == NIC_Setting_Button) {

				NILayer NI = (NILayer) m_LayerMgr.GetLayer("NI");
				IPLayer IP = (IPLayer) m_LayerMgr.GetLayer("IP");
				EthernetLayer ETH = (EthernetLayer) m_LayerMgr.GetLayer("Eth");
				ARPLayer ARP = (ARPLayer) m_LayerMgr.GetLayer("ARP");

				if (NIC_Setting_Button.getText() == "Reset") {
					IP.SetIP_srcaddr("00.00.00.00");
					ETH.Setenet_srcaddr("00-00-00-00-00-00");
					ARP.SetIP_srcaddr("00.00.00.00");
					ARP.SetMAC_srcaddr("00-00-00-00-00-00");
					NI.SetAdapterNumber(0);
					srcMACAddress.setText("");
					NIC_Setting_Button.setText("Setting");
					NICComboBox.setEnabled(true);
				} else {

					List<PcapIf> l = NI.m_pAdapterList;
					String src_mac = "";
					String src_ip = "";
					int index = NICComboBox.getSelectedIndex();
					try {
						byte[] address = l.get(index).getHardwareAddress();
						int j = 0;
						for (byte inetAddress : address) {
							src_mac += String.format("%02x", inetAddress);
							if (j++ != address.length - 1)
								src_mac += "-";
						}

						List<PcapAddr> addr = l.get(index).getAddresses();
						String[] token = addr.get(0).getAddr().toString().split("\\.");
						if (token[0].contains("INET6"))
							return;
						src_ip = token[0].substring(7, token[0].length()) + "." + token[1] + "." + token[2] + "."
								+ token[3].substring(0, token[3].length() - 1);
						System.out.println(src_ip);
						System.out.println(src_mac);
					} catch (IOException e1) {
						e1.printStackTrace();
					}

					IP.SetIP_srcaddr(src_ip);
					ETH.Setenet_srcaddr(src_mac);
					ARP.SetIP_srcaddr(src_ip);
					ARP.SetMAC_srcaddr(src_mac);
					NI.SetAdapterNumber(index);

					srcMACAddress.setText(src_mac);
					NIC_Setting_Button.setText("Reset");
					NICComboBox.setEnabled(false);
				}
			} else if (e.getSource() == Chat_send_Button) {
				String text = ChattingWrite.getText();
				if (text.length() == 0 || NIC_Setting_Button.getText() == "Setting")
					return;
				byte[] input = text.getBytes();
				((IPLayer) m_LayerMgr.GetLayer("IP")).SetIP_dstaddr(dstIPAddress.getText());
				ChattingWrite.setText("");
				GetUnderLayer().Send(input, input.length);

				ChattingArea.append("[SEND] : ");
				ChattingArea.append(text);
				ChattingArea.append("\n");
			}

		}
	}

	public boolean Receive(byte[] input) {
		try {
			ChattingArea.append("[RECV] : ");
			ChattingArea.append(new String(input, "UTF-8"));
			ChattingArea.append("\n");
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

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
