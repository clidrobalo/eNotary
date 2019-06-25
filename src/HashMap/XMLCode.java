package HashMap;

import java.beans.XMLDecoder;
import java.beans.XMLEncoder;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.HashMap;


public class XMLCode {
	
	public static HashMap<String,Integer> fileToMapString_Integer(String fileName) {
		HashMap<String,Integer > t = null;
		try{
			XMLDecoder decoder = new XMLDecoder(new BufferedInputStream(
					new FileInputStream(fileName)));
			t = (HashMap<String, Integer>)decoder.readObject();
			decoder.close();

		}
		catch(Exception e){
			//System.out.println(e);
		}
		return t;
	}

	public static HashMap<String,String> fileToMapString_String(String fileName) {
		HashMap<String,String > t = null;
		try{
			XMLDecoder decoder = new XMLDecoder(new BufferedInputStream(
					new FileInputStream(fileName)));
			t = (HashMap<String, String>)decoder.readObject();
			decoder.close();

		}
		catch(Exception e){
			//System.out.println(e);
		}
		return t;
	}

	public static HashMap<String,Boolean> fileToMapString_Boolean(String fileName) {
		HashMap<String,Boolean > t = null;
		try{
			XMLDecoder decoder = new XMLDecoder(new BufferedInputStream(
					new FileInputStream(fileName)));
			t = (HashMap<String, Boolean>)decoder.readObject();
			decoder.close();

		}
		catch(Exception e){
			//System.out.println(e);
		}
		return t;
	}

	public static boolean mapToFileString_Integer(String fileName, HashMap<String, Integer> t){
		try{
			XMLEncoder encoder = new XMLEncoder( new BufferedOutputStream(
					new FileOutputStream(fileName)));
			encoder.writeObject(t);
			encoder.close();
		}
		catch(Exception e){
			return false;
		}
		return true;
	}

	public static boolean mapToFileString_String(String fileName, HashMap<String, String> t){
		try{
			XMLEncoder encoder = new XMLEncoder( new BufferedOutputStream(
					new FileOutputStream(fileName)));
			encoder.writeObject(t);
			encoder.close();
		}
		catch(Exception e){
			return false;
		}
		return true;
	}

	public static boolean mapToFileString_Boolean(String fileName, HashMap<String, Boolean> t){
		try{
			XMLEncoder encoder = new XMLEncoder( new BufferedOutputStream(
					new FileOutputStream(fileName)));
			encoder.writeObject(t);
			encoder.close();
		}
		catch(Exception e){
			return false;
		}
		return true;
	}
}
