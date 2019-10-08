package arp_test;


import java.util.ArrayList;
import java.util.StringTokenizer;


public class TCPLayer implements BaseLayer {
	public int nUpperLayerCount = 0;
	public String pLayerName = null;
	public BaseLayer p_UnderLayer = null;
	public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();


	private class _TCP {		// HEADER + data 
		
		_TCP_ADDR tcp_sport;
		_TCP_ADDR tcp_dport;
		byte[] tcp_seq;
		byte[] tcp_ack;
		byte tcp_offset;
		byte tcp_flag;
		byte[] tcp_window;
		byte[] tcp_cksum;
		byte[] tcp_urgtr;
		byte[] padding;
		byte[] tcp_data;
		
		public _TCP() {
			
			this.tcp_sport =  new _TCP_ADDR();
			this.tcp_dport = new _TCP_ADDR();
			this.tcp_seq = new byte[4];
			this.tcp_ack = new byte[4];
			this.tcp_offset = 0x00;
			this.tcp_flag = 0x00;
			this.tcp_window = new byte[2];
			this.tcp_cksum = new byte[2];
			this.tcp_urgtr = new byte[2];
			this.padding = new byte[4];
			this.tcp_data = null;
		}	
		
		private class _TCP_ADDR {
			private byte[] addr = new byte[2];
			
			public _TCP_ADDR() {
				this.addr[0] = (byte) 0x00;
				this.addr[1] = (byte) 0x00;
			}
		}
	}

	_TCP m_sHeader = new _TCP();

	public TCPLayer(String pName) {
		
		pLayerName = pName;
		ResetHeader();
	}

	public void ResetHeader() {
		
		for (int i = 0; i < 2; i++) {
			m_sHeader.tcp_sport.addr[i] =  0x00;
			m_sHeader.tcp_dport.addr[i] =  0x00;
			m_sHeader.tcp_window[i] = 0x00;
			m_sHeader.tcp_cksum[i] = 0x00;
			m_sHeader.tcp_urgtr[i] = 0x00;
		}
		
		for (int i = 0; i < 4; i++) {
			m_sHeader.tcp_seq[i] = 0x00;
			m_sHeader.tcp_ack[i] = 0x00;
			m_sHeader.padding[i] = 0x00;
		}
		
		m_sHeader.tcp_offset = 0x00;
		m_sHeader.tcp_flag = 0x00;
		m_sHeader.tcp_data = null;
	}

	public byte[] ObjToByte(_TCP Header, byte[] input, int length) {
		byte[] buf = new byte[length + 24];
		
		for (int i = 0; i < 2; i++) {
			buf[0+i] = Header.tcp_sport.addr[i];
			buf[2+i] = Header.tcp_dport.addr[i];
			buf[14+i] = Header.tcp_window[i];
			buf[16+i] = Header.tcp_cksum[i];
			buf[18+i] = Header.tcp_urgtr[i];
		}
		
		for (int i = 0; i < 4; i++) {
			buf[4+i] = Header.tcp_seq[i];
			buf[8+i] = Header.tcp_ack[i];
			buf[20+i] = Header.padding[i];
		}
		
		buf[12] = Header.tcp_offset;
		buf[13] = Header.tcp_flag;

		for (int i = 0; i < length; i++)
			buf[24 + i] = input[i];

		return buf;
	}

	public boolean Send(byte[] input, int length) {
		byte[] send = ObjToByte(m_sHeader, input, length);
		p_UnderLayer.Send(send, send.length); // IP

		return true;
	}
	

	public byte[] RemoveIPHeader(byte[] input, int length) {
		
		byte[] buf = new byte[length - 24];

		for (int i = 24; i < length; i++)
			buf[i-24] = input[i];

		return buf;
	}

	public synchronized boolean Receive(byte[] input) {

		byte[] data = RemoveIPHeader(input, input.length);
		
		// dport ?ㄸ
		for (int i = 0; i < 2; i++) {
			if (input[i] != m_sHeader.tcp_dport.addr[i]) 
				return false;
		}
		
		this.GetUpperLayer(0).Receive(data); // GUI
		return true;
	}
	
	

	public void SetTCP_dstaddr(int address) {
		byte[] bytes = intToByte2(address);
		
		for(int i = 0; i < 2; i++)
			m_sHeader.tcp_sport.addr[i] = bytes[i];
		 
	}
	
	public void SetTCP_srcaddr(int address) {
		byte[] bytes = intToByte2(address);
		
		for(int i = 0; i < 2; i++)
			m_sHeader.tcp_sport.addr[i] = bytes[i];
		 
	}
	
	byte[] intToByte2(int value) {
		byte[] temp = new byte[2];

		temp[1] = (byte) ((value >> 8) & 0xFF); 
		temp[0] = (byte) (value & 0xFF);
		return temp;
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


}
