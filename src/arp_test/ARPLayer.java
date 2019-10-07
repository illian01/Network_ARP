package arp_test;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.StringTokenizer;

public class ARPLayer implements BaseLayer {
	public int nUpperLayerCount = 0;
	public String pLayerName = null;
	public BaseLayer p_UnderLayer = null;
	public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();
	
	private Map<String, String> cacheTable = new HashMap<>();
	
	private _ARP_Packet m_sHeader = new _ARP_Packet();
	
	private class _ARP_Packet {
		_MAC_ADDR src_mac_addr;
		_MAC_ADDR dst_mac_addr;
		_IP_ADDR src_ip_addr;
		_IP_ADDR dst_ip_addr;
		
		byte[] hardware_type;
		byte[] protocol_type;
		byte hardware_addr_len;
		byte protocol_addr_len;
		byte[] opcode;
		
		public _ARP_Packet() {
			src_mac_addr = new _MAC_ADDR();
			dst_mac_addr = new _MAC_ADDR();
			src_ip_addr = new _IP_ADDR();
			dst_ip_addr = new _IP_ADDR();
			
			hardware_type = new byte[2];
			protocol_type = new byte[2];
			hardware_addr_len = (byte) 0x00;
			protocol_addr_len = (byte) 0x00;
			opcode = new byte[2];
		}
		
		private class _MAC_ADDR {
			private byte[] addr = new byte[6];
			
			public _MAC_ADDR() {
				this.addr[0] = (byte) 0x00;
				this.addr[1] = (byte) 0x00;
				this.addr[2] = (byte) 0x00;
				this.addr[3] = (byte) 0x00;
				this.addr[4] = (byte) 0x00;
				this.addr[5] = (byte) 0x00;
			}
		}
		
		private class _IP_ADDR {
			private byte[] addr = new byte[4];
			
			public _IP_ADDR() {
				this.addr[0] = (byte) 0x00;
				this.addr[1] = (byte) 0x00;
				this.addr[2] = (byte) 0x00;
				this.addr[3] = (byte) 0x00;
			}
		}
		
	}

	public ARPLayer(String pName) {
		pLayerName = pName;
		setHeader();
	}
	
	public void setHeader() {
		m_sHeader.hardware_type[0] = (byte) 0x00;
		m_sHeader.hardware_type[1] = (byte) 0x01;
		m_sHeader.protocol_type[0] = (byte) 0x08;
		m_sHeader.protocol_type[1] = (byte) 0x00;
		m_sHeader.hardware_addr_len = (byte) 0x06;
		m_sHeader.protocol_addr_len = (byte) 0x04;
		m_sHeader.opcode[0] = (byte) 0x00;
		m_sHeader.opcode[1] = (byte) 0x01;
		m_sHeader.dst_mac_addr.addr[0] = (byte) 0xFF;
		m_sHeader.dst_mac_addr.addr[1] = (byte) 0xFF;
		m_sHeader.dst_mac_addr.addr[2] = (byte) 0xFF;
		m_sHeader.dst_mac_addr.addr[3] = (byte) 0xFF;
		m_sHeader.dst_mac_addr.addr[4] = (byte) 0xFF;
		m_sHeader.dst_mac_addr.addr[5] = (byte) 0xFF;
	}
	
	public byte[] gen_ARP_msg() {
		byte[] msg = new byte[28];
		
		msg[0] = m_sHeader.hardware_type[0];
		msg[1] = m_sHeader.hardware_type[1];
		msg[2] = m_sHeader.protocol_type[0];
		msg[3] = m_sHeader.protocol_type[1];
		msg[4] = m_sHeader.hardware_addr_len;
		msg[5] = m_sHeader.protocol_addr_len;
		msg[6] = m_sHeader.opcode[0];
		msg[7] = m_sHeader.opcode[1];
		msg[8] = m_sHeader.src_mac_addr.addr[0];
		msg[9] = m_sHeader.src_mac_addr.addr[1];
		msg[10] = m_sHeader.src_mac_addr.addr[2];
		msg[11] = m_sHeader.src_mac_addr.addr[3];
		msg[12] = m_sHeader.src_mac_addr.addr[4];
		msg[13] = m_sHeader.src_mac_addr.addr[5];
		msg[14] = m_sHeader.src_ip_addr.addr[0];
		msg[15] = m_sHeader.src_ip_addr.addr[1];
		msg[16] = m_sHeader.src_ip_addr.addr[2];
		msg[17] = m_sHeader.src_ip_addr.addr[3];
		msg[18] = m_sHeader.dst_mac_addr.addr[0];
		msg[19] = m_sHeader.dst_mac_addr.addr[1];
		msg[20] = m_sHeader.dst_mac_addr.addr[2];
		msg[21] = m_sHeader.dst_mac_addr.addr[3];
		msg[22] = m_sHeader.dst_mac_addr.addr[4];
		msg[23] = m_sHeader.dst_mac_addr.addr[5];
		msg[24] = m_sHeader.dst_ip_addr.addr[0];
		msg[25] = m_sHeader.dst_ip_addr.addr[1];
		msg[26] = m_sHeader.dst_ip_addr.addr[2];
		msg[27] = m_sHeader.dst_ip_addr.addr[3];
		
		return msg;
	}

	public boolean Send(byte[] input, int length) {
		String dst_addr = getIPAddr(input);
		if(!cacheTable.containsKey(dst_addr)) {
			String[] token = dst_addr.split("\\.");
			m_sHeader.dst_ip_addr.addr[0] = (byte) Integer.parseInt(token[0]);
			m_sHeader.dst_ip_addr.addr[1] = (byte) Integer.parseInt(token[1]);
			m_sHeader.dst_ip_addr.addr[2] = (byte) Integer.parseInt(token[2]);
			m_sHeader.dst_ip_addr.addr[3] = (byte) Integer.parseInt(token[3]);
			
			byte[] msg = gen_ARP_msg();
			GetUnderLayer().Send(msg, msg.length);
		}
		
		return true;
	}

	public synchronized boolean Receive(byte[] input) {
		return true;
	}
	
	private String getIPAddr(byte[] input) {
		byte[] addr = new byte[input.length-48];
		
		for(int i = 0; i < addr.length; i++)
			addr[i] = input[i+48];
		return new String(addr);
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
	public void SetUpperUnderLayer(BaseLayer pUULayer) {
		this.SetUpperLayer(pUULayer);
		pUULayer.SetUnderLayer(this);
	}
	
	public void SetMAC_dstaddr(String address) {
		StringTokenizer st = new StringTokenizer(address, "-");
		
		for(int i = 0; i < 6; i++)
			m_sHeader.dst_mac_addr.addr[i] = (byte) Integer.parseInt(st.nextToken(), 16);
		 
	}
	
	public void SetMAC_srcaddr(String address) {
		StringTokenizer st = new StringTokenizer(address, "-");
		
		for(int i = 0; i < 6; i++)
			m_sHeader.src_mac_addr.addr[i] = (byte) Integer.parseInt(st.nextToken(), 16);
		 
	}
	
	public void SetIP_dstaddr(String address) {
		StringTokenizer st = new StringTokenizer(address, ".");
		
		for(int i = 0; i < 4; i++)
			m_sHeader.dst_ip_addr.addr[i] = (byte) Integer.parseInt(st.nextToken());
	}
	
	public void SetIP_srcaddr(String address) {
		StringTokenizer st = new StringTokenizer(address, ".");
		
		for(int i = 0; i < 4; i++)
			m_sHeader.src_ip_addr.addr[i] = (byte) Integer.parseInt(st.nextToken());
	}


}