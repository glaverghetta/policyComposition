package edu.cseusf.poco.poco_demo.polymerPolicies;

import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.PrintStream;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.mail.Address;
import javax.mail.BodyPart;
import javax.mail.Header;
import javax.mail.Message;
import javax.mail.Multipart;
import javax.mail.Part;
import javax.mail.internet.MimePart;
import javax.swing.JOptionPane;

import edu.cseusf.poco.event.Action;
import edu.cseusf.poco.event.Event;
import edu.cseusf.poco.event.Result;
import edu.cseusf.poco.poco_demo.polymerPolicies.absactions.GetMailContent;
import edu.cseusf.poco.poco_demo.polymerPolicies.absactions.GetMailSubject;
import edu.cseusf.poco.poco_demo.polymerPolicies.absactions.ReceiveEmail;
import edu.cseusf.poco.policy.GrayPolicy;

/**
 * This policy enforces the following: - Mail from unknown addresses has "SPAM?
 * - " prepended to subject (when message subject is queried at a high-level;
 * doesn't mess with messages' raw bytes)
 */

public class SpamPolicy extends GrayPolicy {

	private static final String addrFilename = "/src/main/java/edu/cseusf/poco/poco_demo/known.addrs";
	private static Hashtable<String, LocalDateTime> warnedTable = new Hashtable<>();
	private Action getMailSubject, getMailContent, recvEmail; 
	private final DateTimeFormatter formatter = DateTimeFormatter.ofPattern("EEE, d MMM uuuu HH:mm:ss Z '('z')'");
	
	private ArrayList<String> trustedAddrs;
	private String msg = "This message contains an attachment that, if opened,"
			+ " could seriously harm\nyour computer.  Unless you specifically asked the sender for"
			+ " this attachment,\nit is strongly recommended that you delete this message immediately.";
	
	private Map<String, String> emailAttachmentWarnings = new HashMap<String, String>();
	
	
	// If a sender's security rating is >= SECURTIY_RATING_INTERVALS[i], then the message SPAM_WARNINGS[i] should be prepended to their emails.
	// SECURTIY_RATING_INTERVALS.length must equal SPAM_WARNINGS.length
	private static final int[] SECURTIY_RATING_INTERVALS = {SECURITY_VALUE_MAX, 90, 70, 50, SECURITY_VALUE_MIN};
	private static final String[] SPAM_WARNINGS = {"", "POSSIBLE SPAM: ", "LIKELY SPAM: ", "WARNING! LIKELY SPAM: ", "DANGER! VERY LIKELY SPAM: "};

	// Map: Sender's email address -> number of spam emails they have sent
	private Map<String, Integer> senderEmailsSent = new HashMap<String, Integer>();
	
	// Map: Email message -> email's security rating
	private Map<Message, Integer> sentEmailsSecurityRatings = new HashMap<Message, Integer>();
	
	// Set: dates of sent emails
	private HashSet<Date> sentEmailsDates = new HashSet<Date>();
	

	public SpamPolicy() {
		emailAttachmentWarnings.put(".txt", "This attachment is safe");
		emailAttachmentWarnings.put(".zip", "Caution - this zip archive may contain dangerous files");
		emailAttachmentWarnings.put(".c", "Warning - do not compile and run untrusted source code");
		emailAttachmentWarnings.put(".exe", "Danger - do NOT run executable files unless you trush the sender!");
		emailAttachmentWarnings.put(".docm", "Extreme Danger - this office file may contain macro code that can seriously harm your computer!!!");
		
		trustedAddrs = new ArrayList<>();
		File file = new File(Paths.get("").toAbsolutePath() + addrFilename);
		if (!file.exists() || file.isDirectory()) missingAddrBook();
		try (BufferedReader br = new BufferedReader(new FileReader(file))) {
			while (br.ready()) {
				String s = br.readLine();
				if (s != null && s.trim().equals("") == false) {
					String addr = s.trim().toLowerCase();
					trustedAddrs.add(addr.replace("@", "\\@").replace(".", "\\.").replace("*", ".+") );
				}
			}
			if (trustedAddrs.size() == 0) missingAddrBook();

			getMailSubject  = new GetMailSubject(trustedAddrs.get(0));
			getMailContent  = new GetMailContent(trustedAddrs.get(0));
			recvEmail =  new ReceiveEmail();

		} catch (Exception e) {
			System.err.println("Exception in SpamEmail policy: ");
			e.printStackTrace();
			System.exit(1);
		}
		
	}
	// For the spam email gray policy, the security rating of the policy is defined as the security rating of the sender with the lowest rating.
	@Override
	public int getSecurityValue() {
		int min = SECURITY_VALUE_MAX;
		if(senderEmailsSent.size() == 0)
			return min;
		else {
			for(int emailsSent : senderEmailsSent.values()) {
				int senderValue = getSenderSecurityValue(emailsSent);
				if(min < senderValue)
					min = senderValue;
			}
		}
		return min;
	}
	
	// Based on the number of spam emails that the source address has sent, this returns their security rating
	// function used: M - x^2
	private int getSenderSecurityValue(int numEmails) {
		return Math.max(SECURITY_VALUE_MIN, SECURITY_VALUE_MAX - (numEmails * numEmails));
	}
	
	public void onTrigger(Event e) {
		if (e.isAction() && e.matches(getMailSubject)) {
			Message mime = (Message) e.getCaller();
			try {
				String subj = mime.getSubject();
				// Check is this is a trusted sender
				if(!isSenderKnown(mime)) {
					// Check if this email was already checked
					if(!sentEmailsDates.contains(mime.getSentDate())) { 
						//System.out.println("currently examining message with message number " + mime.getMessageNumber() + " and date " + mime.getSentDate().toString());
						sentEmailsDates.add(mime.getSentDate());
						String sender = mime.getHeader("From")[0];
					
						if(!senderEmailsSent.containsKey(sender)) {
							senderEmailsSent.put(sender, 0);
						}
						int numEmails = senderEmailsSent.get(sender);
						int senderSecurityValue = getSenderSecurityValue(numEmails);
						//System.out.println(sender + "'s security value is " + senderSecurityValue);
					
						String message = "";
						for(int i = 0; i < SECURTIY_RATING_INTERVALS.length; i++) {
							if(senderSecurityValue >= SECURTIY_RATING_INTERVALS[i]) {
								//System.out.println("i = " + i + " and " + senderSecurityValue + " >= " + SECURTIY_RATING_INTERVALS[i]);
								message = SPAM_WARNINGS[i];
								break;
							}
						}
					
						subj = senderSecurityValue + " " + message + subj;
					
						sentEmailsSecurityRatings.put(mime, senderSecurityValue);
						senderEmailsSent.put(sender, numEmails + 1);		
					}
					else {
						int sentEmailSecurityRating = sentEmailsSecurityRatings.get(mime);
						//System.out.println(mime.getSubject() + "'s security value is " + sentEmailSecurityRating);
						String message = "none";
						for(int i = 0; i < SECURTIY_RATING_INTERVALS.length; i++) {
							if(sentEmailSecurityRating >= SECURTIY_RATING_INTERVALS[i]) {
								//System.out.println("i = " + i + " and " + sentEmailSecurityRating + " >= " + SECURTIY_RATING_INTERVALS[i]);
								message = SPAM_WARNINGS[i];
								break;
							}
						}
						subj = sentEmailSecurityRating + " " + message + subj;
					
					}
				}
				setOutput(new Result(e, subj));
			} catch (Exception ex) {}
		} 
		
		else if (e.isAction() && e.matches(getMailContent)) {
			boolean isknown = false;
			MimePart part= (MimePart) e.getCaller(); 
			try {
				String[] sa = part.getHeader("From");
			    if(sa!=null && sa.length >0) 
			    	isknown = checkSender(sa[0]);
			    if(!isknown && getAttachment(part) != "") {
			    	String fileExtension = getAttachment(part);
			    	System.out.println(fileExtension);
			    	String sender = part.getHeader("From")[0];
			    	sender = sender.toLowerCase();
					String[] dt = part.getHeader("Date");
					LocalDateTime ldt =  (dt != null && dt[0] != null) ? LocalDateTime.parse(dt[0], formatter)
																	   : LocalDateTime.now();
					
					ldt = ldt.truncatedTo(ChronoUnit.MINUTES);
					if (!warnedTable.containsKey(sender) || warnedTable.get(sender).isBefore(ldt)) {
						warnedTable.put(sender, ldt);
						JOptionPane.showMessageDialog(null, emailAttachmentWarnings.get(fileExtension), "BEWARE", 0);
					}
			    }
			} catch (Exception e1) { }
		} 
		/*else if (e.isResult() && e.matches(recvEmail)) {
			logMailMsg(((Result) e).getEvtRes());
		}*/
	}
	
	// returns attachment file extension, or "" if no attachments
	private String getAttachment(Part mm) {
		try {
			if (mm == null || mm.getContent() == null)
				return "";

			Object content = mm.getContent();

			if (content instanceof Multipart) {
				Multipart mp = (Multipart) content;
				for (int i = 0; i < mp.getCount(); i++) {
					if (getAttachment(mp.getBodyPart(i)) != "") {
						String fileName = mp.getBodyPart(i).getFileName();
						int indexOfPeriod = fileName.indexOf(".");
						return fileName.substring(indexOfPeriod);
					}
				}
				return "";
			} else {
				if (mm.getContentType() == null)
					return "";
				
				//String type = mm.getContentType();
				//type = type.toUpperCase();
				String fileName = mm.getFileName();
				int indexOfPeriod = fileName.indexOf(".");
				String fileExtension = fileName.substring(indexOfPeriod);
				
				//System.out.println("content type of this attachment is " + type);
				//System.out.println("file extension of this attachment is " + fileExtension);
				//if (type.startsWith("TEXT/PLAIN") || type.startsWith("TEXT/HTML") || type.startsWith("MESSAGE/RFC822"))
				return fileExtension;
			}
		} catch (Exception e) {
			return "";
		}
	}
	

	private void missingAddrBook() {
		System.out.println("<IncomingMail> Error: you must have a file known.addrs");
		System.out.println("that contains your address book, one email address");
		System.out.println("per line, with your email address on the first line");
		System.exit(1);
	}
	
	private boolean isSenderKnown(Message mime) {
		try {
			String sender = mime.getHeader("From")[0];
			sender = sender.toLowerCase();
			return checkSender(sender);
		} catch (Exception e) { }
		return false;
	}
	private boolean checkSender(String addr) {
		for (int i = 0; i < trustedAddrs.size(); i++) {
			Pattern pattern = Pattern.compile(trustedAddrs.get(i));
			Matcher matcher = pattern.matcher(addr);
			if( matcher.find())
				return true;
		}
		return false;
	}

}
