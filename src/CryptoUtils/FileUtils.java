/**
 * 
 * Description:
 * Class containing methods related to 
 * files I/O operations
 * 
 * Version: 
 * 04.2019
 * 
 * Author: 
 * Jose G. Faisca <jose.faisca@gmail.com>
 * 
 */

package CryptoUtils;

import java.io.*;

public class FileUtils {

	/**
	 * Save a string to file
	 * 
	 * @param str
	 * 		  the string to read		  
	 * @param fileName
	 *        the destination file name                                    
	 * @throws Exception
	 */	
	public static void saveStrToFile(String str, String fileName) throws Exception {
		File newTextFile = new File(fileName);
		FileWriter fw = new FileWriter(newTextFile);
		fw.write(str);
		fw.close();    
	}	

	/**
	 * Read from regular file (multiple lines) to string
	 * 
	 * @param fileName
	 *        the file name to read 
	 * @param charEncoding 
	 *        the file character encoding (UTF8, ASCII,..)                
	 * @return the string                
	 * @throws Exception
	 */	
	public static String readFileToString(String fileName, String charEncoding) throws Exception {
		File file = new File(fileName);
		BufferedReader in = null;
		in = new BufferedReader(
				new InputStreamReader(new FileInputStream(file), charEncoding));
		String line = in.readLine();
		StringBuilder sb = new StringBuilder();
		while(line != null){
			sb.append(line).append("\n");
			line = in.readLine();
		}
		in.close();
		return sb.toString(); 	
	}	

	/**
	 * Read from simple file (one line) to string
	 * 
	 * @param fileName
	 *        the file name to read 
	 * @param charEncoding 
	 *        the file character encoding (UTF8, ASCII,..)                
	 * @return the string                
	 * @throws Exception
	 */	
	public static String readSimpleFileToString(String fileName, String charEncoding) throws Exception {
		String plainText = null;
		File file = new File(fileName);
		BufferedReader in = null;
		in = new BufferedReader(
				new InputStreamReader(new FileInputStream(file), charEncoding));
		plainText = in.readLine();  
		in.close(); 
		return plainText;
	}
}
