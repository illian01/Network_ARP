package arp_test;

import java.nio.ByteBuffer;
import java.util.ArrayList;

public class AppLayer implements BaseLayer {
	public int nUpperLayerCount = 0;
	public String pLayerName = null;
	public BaseLayer p_UnderLayer = null;
	public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();
	public ByteBuffer buf = ByteBuffer.allocate(2048);

	private class _CHAT_APP {
		byte[] capp_totlen;
		byte capp_type;
		byte capp_unused;
		byte[] capp_data;

		public _CHAT_APP() {
			this.capp_totlen = new byte[2];
			this.capp_type = 0x00;
			this.capp_unused = 0x00;
			this.capp_data = new byte[10];
		}
	}

	_CHAT_APP m_sHeader = new _CHAT_APP();

	public AppLayer(String pName) {
		pLayerName = pName;
		ResetHeader();
	}

	public void ResetHeader() {
		for (int i = 0; i < 2; i++)
			m_sHeader.capp_totlen[i] = (byte) 0x00;
		m_sHeader.capp_data = null;
	}

	public byte[] ObjToByte(_CHAT_APP Header, byte[] input, int length) {
		byte[] buf = new byte[length + 4];

		buf[0] = Header.capp_totlen[0];
		buf[1] = Header.capp_totlen[1];
		buf[2] = Header.capp_type;
		buf[3] = Header.capp_unused;

		for (int i = 0; i < length; i++)
			buf[4 + i] = input[i];

		return buf;
	}

	public synchronized boolean Send(byte[] input, int length) {
		Send_Thread thread = new Send_Thread(input, length);
		Thread send = new Thread(thread);
		send.start();
		
		return true;
	}

	public byte[] RemoveCappHeader(byte[] input, int length) {
		byte[] buf = new byte[length - 4];

		for (int i = 4; i < length; i++)
			buf[i - 4] = input[i];

		return buf;
	}

	public synchronized boolean Receive(byte[] input) {
		
		int totalLength = (input[0] & 0xFF) * 256 | (input[1] & 0xFF);
		if (totalLength != input.length - 4) return false;
		
		byte[] data;
		data = RemoveCappHeader(input, input.length);
		this.GetUpperLayer(1).Receive(data);
		return true;
	}
	
	class Send_Thread implements Runnable { // Send Thread
		byte[] sendData; // data for sending
	
		public Send_Thread(byte[] input, int length) {
			m_sHeader.capp_totlen[0] = (byte) (length / 256);
			m_sHeader.capp_totlen[1] = (byte) (length % 256);

			sendData = ObjToByte(m_sHeader, input, length);
		}
		
		public void run() {
			while(true) {
				p_UnderLayer.Send(sendData, sendData.length);
			}
		}
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
