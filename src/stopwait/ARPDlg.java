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

	private JTextField ChattingWrite;

	Container contentPane;

	JTextArea ChattingArea;
	JTextArea srcMACAddress;
	JTextArea dstMACAddress;

	JLabel lblNIC;
	JLabel lblsrc;
	JLabel lbldst;

	JButton Setting_Button;
	JButton Chat_send_Button;

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

		setTitle("SWP");
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setBounds(250, 250, 644, 425);
		contentPane = new JPanel();
		((JComponent) contentPane).setBorder(new EmptyBorder(5, 5, 5, 5));
		setContentPane(contentPane);
		contentPane.setLayout(null);

		JPanel chattingPanel = new JPanel();// chatting panel
		chattingPanel.setBorder(new TitledBorder(UIManager.getBorder("TitledBorder.border"), "chatting",
				TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		chattingPanel.setBounds(10, 5, 360, 276);
		contentPane.add(chattingPanel);
		chattingPanel.setLayout(null);

		JPanel chattingEditorPanel = new JPanel();// chatting write panel
		chattingEditorPanel.setBounds(10, 15, 340, 210);
		chattingPanel.add(chattingEditorPanel);
		chattingEditorPanel.setLayout(null);

		ChattingArea = new JTextArea();
		ChattingArea.setEditable(false);
		ChattingArea.setBounds(0, 0, 340, 210);
		chattingEditorPanel.add(ChattingArea);// chatting edit

		JPanel chattingInputPanel = new JPanel();// chatting write panel
		chattingInputPanel.setBorder(new BevelBorder(BevelBorder.LOWERED, null, null, null, null));
		chattingInputPanel.setBounds(10, 230, 250, 20);
		chattingPanel.add(chattingInputPanel);
		chattingInputPanel.setLayout(null);

		ChattingWrite = new JTextField();
		ChattingWrite.setBounds(2, 2, 250, 20);// 249
		chattingInputPanel.add(ChattingWrite);
		ChattingWrite.setColumns(10);// writing area

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

		lblNIC = new JLabel("NIC선택");
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
		sourceAddressPanel.add(srcMACAddress);// src address

		JPanel destinationAddressPanel = new JPanel();
		destinationAddressPanel.setBorder(new BevelBorder(BevelBorder.LOWERED, null, null, null, null));
		destinationAddressPanel.setBounds(10, 212, 170, 20);
		settingPanel.add(destinationAddressPanel);
		destinationAddressPanel.setLayout(null);

		lbldst = new JLabel("Destination Mac Address");
		lbldst.setBounds(10, 187, 190, 20);
		settingPanel.add(lbldst);

		dstMACAddress = new JTextArea();
		dstMACAddress.setBounds(2, 2, 170, 20);
		destinationAddressPanel.add(dstMACAddress);// dst address

		Setting_Button = new JButton("Setting");// setting
		Setting_Button.setBounds(80, 270, 100, 20);
		Setting_Button.addActionListener(new setAddressListener());
		settingPanel.add(Setting_Button);// setting

		Chat_send_Button = new JButton("Send");
		Chat_send_Button.setBounds(270, 230, 80, 20);
		Chat_send_Button.addActionListener(new setAddressListener());
		chattingPanel.add(Chat_send_Button);// chatting send button

		setVisible(true);

	}

	class setAddressListener implements ActionListener {
		@Override
		public void actionPerformed(ActionEvent e) {
			if (e.getSource() == NICComboBox) {
				srcMACAddress.setText("");
				NILayer NI = (NILayer) m_LayerMgr.GetLayer("NI");
				List<PcapIf> l = NI.m_pAdapterList;
				try {
					byte[] address = l.get(NICComboBox.getSelectedIndex()).getHardwareAddress();
					int j = 0;
					for (byte inetAddress : address) {
						srcMACAddress.append(String.format("%02x", inetAddress));
						if (j++ != address.length - 1)
							srcMACAddress.append("-");
					}
				} catch (IOException e1) {
					e1.printStackTrace();
				}
			} else if (e.getSource() == Setting_Button) {
				if (Setting_Button.getText().equals("Setting")) {
					
					if (dstMACAddress.getText().equals("") || srcMACAddress.getText().equals("")) {
						JOptionPane.showMessageDialog(null, "입력이 없습니다!");
					}
					else {
						NILayer NI = (NILayer) m_LayerMgr.GetLayer("NI");
						EthernetLayer Eth = (EthernetLayer) m_LayerMgr.GetLayer("Eth");

						Eth.Setenet_dstaddr(dstMACAddress.getText());
						Eth.Setenet_srcaddr(srcMACAddress.getText());
						int i = NICComboBox.getSelectedIndex();
						NI.SetAdapterNumber(i);

						dstMACAddress.setEnabled(false);
						srcMACAddress.setEnabled(false);
						NICComboBox.setEnabled(false);
						Setting_Button.setText("Reset");
					}
				} else {
					dstMACAddress.setEnabled(true);
					srcMACAddress.setEnabled(true);
					NICComboBox.setEnabled(true);
					dstMACAddress.setText("");
					Setting_Button.setText("Setting");
				}
			} else if (e.getSource() == Chat_send_Button) {
				if (Setting_Button.getText().equals("Setting")) {
					JOptionPane.showMessageDialog(null, "주소 설정을 먼저 하십시오.");					
				}
				else {
					byte[] input = ChattingWrite.getText().getBytes();
					ChattingArea.append("[SEND]:" + ChattingWrite.getText() + "\n");
					p_UnderLayer.Send(input, input.length);
					ChattingWrite.setText("");
				}
			}
		}
	}

	public boolean Receive(byte[] input) {
		ChattingArea.append("[RECV]:");
		try {
			ChattingArea.append(new String(input, "MS949"));
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		ChattingArea.append("\n");

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
