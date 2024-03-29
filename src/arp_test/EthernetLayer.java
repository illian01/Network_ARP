package arp_test;

import java.util.ArrayList;
import java.util.StringTokenizer;

public class EthernetLayer implements BaseLayer {
	
	private class _ETHERNET_Frame {
		_ETHERNET_ADDR enet_dstaddr;
		_ETHERNET_ADDR enet_srcaddr;
		byte[] enet_type;
		byte[] enet_data;
		
		public _ETHERNET_Frame() {
			this.enet_dstaddr = new _ETHERNET_ADDR();
			this.enet_srcaddr = new _ETHERNET_ADDR();
			this.enet_type = new byte[2];
			this.enet_data = null;
		}
		
		private class _ETHERNET_ADDR {
			private byte[] addr = new byte[6];
			
			public _ETHERNET_ADDR() {
				this.addr[0] = (byte) 0x00;
				this.addr[1] = (byte) 0x00;
				this.addr[2] = (byte) 0x00;
				this.addr[3] = (byte) 0x00;
				this.addr[4] = (byte) 0x00;
				this.addr[5] = (byte) 0x00;
			}
		}
	}
	
	public int nUpperLayerCount = 0;
	public String pLayerName = null;
	public BaseLayer p_UnderLayer = null;
	public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();
	
	_ETHERNET_Frame m_sHeader = new _ETHERNET_Frame();
	
	public EthernetLayer(String pName) {
		
		pLayerName = pName;
	}
	
	public byte[] ObjToByte(_ETHERNET_Frame Header, int length) {
		byte[] buf = new byte[length + 14];
		
		buf[0] = Header.enet_dstaddr.addr[0];	// DA
		buf[1] = Header.enet_dstaddr.addr[1];
		buf[2] = Header.enet_dstaddr.addr[2];
		buf[3] = Header.enet_dstaddr.addr[3];
		buf[4] = Header.enet_dstaddr.addr[4];
		buf[5] = Header.enet_dstaddr.addr[5];
		buf[6] = Header.enet_srcaddr.addr[0];	// SA
		buf[7] = Header.enet_srcaddr.addr[1];
		buf[8] = Header.enet_srcaddr.addr[2];
		buf[9] = Header.enet_srcaddr.addr[3];
		buf[10] = Header.enet_srcaddr.addr[4];
		buf[11] = Header.enet_srcaddr.addr[5];
		buf[12] = Header.enet_type[0];
		buf[13] = Header.enet_type[1];
		
		for (int i = 0; i < length; i++)
			buf[14 + i] = Header.enet_data[i];
		
		return buf;
	}
	
	public byte[] RemoveEtherHeader(byte[] input, int length) {
		byte[] data = new byte[length - 14];
		for (int i = 0; i < length - 14; i++)
			data[i] = input[i + 14];
		return data;
	}
	
	public synchronized boolean Send(byte[] input, int length) {

		byte[] bytes;
		m_sHeader.enet_type[0] = (byte) 0x08;
		m_sHeader.enet_type[1] = (byte) 0x06;
		m_sHeader.enet_data = input;
		
		// Judge ARP Request or not as frame_type
		if(input[6] == 0x00 && input[7] == 0x01) {			    // ARP request 
			m_sHeader.enet_dstaddr.addr[0] = (byte) 0xFF;
			m_sHeader.enet_dstaddr.addr[1] = (byte) 0xFF;
			m_sHeader.enet_dstaddr.addr[2] = (byte) 0xFF;
			m_sHeader.enet_dstaddr.addr[3] = (byte) 0xFF;
			m_sHeader.enet_dstaddr.addr[4] = (byte) 0xFF;
			m_sHeader.enet_dstaddr.addr[5] = (byte) 0xFF;
		}
		else if(input[6] == 0x00 && input[7] == 0x02) {			// ARP reply  
			m_sHeader.enet_dstaddr.addr[0] = input[18];
			m_sHeader.enet_dstaddr.addr[1] = input[19];
			m_sHeader.enet_dstaddr.addr[2] = input[20];
			m_sHeader.enet_dstaddr.addr[3] = input[21];
			m_sHeader.enet_dstaddr.addr[4] = input[22];
			m_sHeader.enet_dstaddr.addr[5] = input[23];
		}
		else { 													// data
			m_sHeader.enet_type[1] = (byte) 0x00;
		}
		 
		bytes = ObjToByte(m_sHeader, input.length);
		if(this.GetUnderLayer().Send(bytes, bytes.length))
			return true;
		else 
			return false;
	}
	
	public synchronized boolean Receive(byte[] input) {

		byte[] bytes; 
		if(!CheckAddress(input)) return false;
		
		if(input[12] == 0x08 && input[13] == 0x06){				// ARP request & ARP reply
			bytes = RemoveEtherHeader(input, input.length);
			this.GetUpperLayer(0).Receive(bytes);
			return true;
		}
		else if(input[12] == 0x08 && input[13] == 0x00) {		// IPv4
			bytes = RemoveEtherHeader(input, input.length);
			this.GetUpperLayer(1).Receive(bytes);
			return true;
		}
		
		return false;
				
	}
	
	public boolean CheckAddress(byte[] packet) {
		
		// srcaddr == my mac addr -> false
		for (int i = 0; i < 6; i++) {
			if(packet[i+6] != m_sHeader.enet_srcaddr.addr[i]) break;
			if(i == 5) return false;
		}
		
		// broadcast -> true
		for (int i = 0; i < 6; i++) { 
			if(packet[i] != (byte) 0xFF)  break;
			if(i == 5) return true;
		}
		
		// dstaddr != my mac addr -> false
		for (int i = 0; i < 6; i++) {
			if(packet[i] != m_sHeader.enet_srcaddr.addr[i])
				return false;
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
	
	public void Setenet_dstaddr(String address) {
		StringTokenizer st = new StringTokenizer(address, "-");
		
		for(int i = 0; i < 6; i++)
			m_sHeader.enet_dstaddr.addr[i] = (byte) Integer.parseInt(st.nextToken(), 16);
		 
	}
	
	public void Setenet_srcaddr(String address) {
		StringTokenizer st = new StringTokenizer(address, "-");
		
		for(int i = 0; i < 6; i++)
			m_sHeader.enet_srcaddr.addr[i] = (byte) Integer.parseInt(st.nextToken(), 16);
		 
	}

}
