/**
 * 
 * Description:
 * Class containing methods related to time/date
 * 
 * Version: 
 * 04.2019
 * 
 * Author: 
 * Jose G. Faisca <jose.faisca@gmail.com>
 * 
 */

package CryptoUtils;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

public class TimeUtils {
	
	/**
	 * Get Unix time 
	 *         
	 * @return the Unix time               
	 */		
	public static long unixTime() {
		return System.currentTimeMillis() / 1000L;
		//return Instant.now().getEpochSecond();
	}

	/**
	 * Get Unix time converted to a time zone date 
	 * 
	 * @param unixTime
	 *        the Unix time to read 
	 * @param timeZone
	 *        the time zone to read            
	 * @return the date and time                
	 */	
	public static String unixTimeToDate(long unixTime, String timeZone) {
		Date date = new Date(unixTime*1000L);
		SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss z");
		sdf.setTimeZone(TimeZone.getTimeZone(timeZone));
		return sdf.format(date);
	}
}
