/*--------------------------------------------------------

1. Cameron Morales 10/28/17 

2. build 1.8.0_111-b14

3. Command-line compilation instructions:

-Individually

>javac Blockchain.java

-Batch From Root Directory

> javac *.java

4. Precise examples / instructions to run this program:

In separate shell windows:

> java Blockchain 0
> java Blockchain 1
> java Blockchain 2

All acceptable commands are displayed on the console.

This program is designed to run on a single machine;
The host machines would need to be specified to run as 
a truly distributed application.

5. List of files needed for running the program.

e.g.:

 a. Blockchain.java
 b. BlockInput0.txt
 c. BlockInput1.txt
 d. BlockInput2.txt
 
 -Additional input files can be used in format: BlockInput[i].txt

5. Notes: 


----------------------------------------------------------*/

/*The JAXB libraries: */
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javafx.util.Pair;
import java.util.regex.*;
import java.security.KeyFactory;
/*Encryption suite libraries*/
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
/*Misc additional libraries*/
import java.util.Date;
import java.util.Random;
import java.util.Scanner;
import java.util.UUID;
import java.util.concurrent.Semaphore;
import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;



@XmlRootElement
class BlockRecord{
	  /* Examples of block fields: */
	  String SHA256String;
	  String SignedSHA256;
	  String VerificationProcessID;
	  String PreviousHash;
	  String Seed;
	  String BlockNum;
	  String BlockID;
	  String SignedBlockID;
	  String CreatingProcess;
	  String DataHash;
	  String Fname;
	  String Lname;
	  String SSNum;
	  String DOB;
	  String Diag;
	  String Treat;
	  String Rx;
	  String Timestamp;

	  /* Setters/Getters for BlockRecord fields, @XmlElement permits easy retrival of field for xml output formatting*/

	  public String getASHA256String() {return SHA256String;}
	  @XmlElement
	    public void setASHA256String(String SH){this.SHA256String = SH;}

	  public String getASignedSHA256() {return SignedSHA256;}
	  @XmlElement
	   	public void setASignedSHA256(String SH){this.SignedSHA256 = SH;}
	  
	  public String getAVerificationProcessID() {return VerificationProcessID;}
	  @XmlElement
	    public void setAVerificationProcessID(String VID){this.VerificationProcessID = VID;}

	  public String getPreviousHash() {return PreviousHash;}
	  @XmlElement
		public void setPreviousHash(String PH) {this.PreviousHash = PH;}
	  
	  public String getSeed() {return Seed;}
	  @XmlElement
		public void setSeed(String Seed) {this.Seed = Seed;}
	  
	  public String getBlockNum() {return BlockNum;}
	  @XmlElement
		public void setBlockNum(String BNum) {this.BlockNum = BNum;}

	  public String getABlockID() {return BlockID;}
	  @XmlElement
	    public void setABlockID(String BID){this.BlockID = BID;}
	  
	  public String getSignedBlockID() {return SignedBlockID;}
	  @XmlElement
	  	public void setSignedBlockID(String SID) {this.SignedBlockID = SID;}
	  
	  public String getACreatingProcess() {return CreatingProcess;}
	  @XmlElement
	    public void setACreatingProcess(String CP){this.CreatingProcess = CP;}
	  
	  public String getDataHash() {return DataHash;}
	  @XmlElement
	  	public void setDataHash(String DH) {this.DataHash = DH;}

	  public String getFSSNum() {return SSNum;}
	  @XmlElement
	    public void setFSSNum(String SS){this.SSNum = SS;}

	  public String getFFname() {return Fname;}
	  @XmlElement
	    public void setFFname(String FN){this.Fname = FN;}

	  public String getFLname() {return Lname;}
	  @XmlElement
	    public void setFLname(String LN){this.Lname = LN;}

	  public String getFDOB() {return DOB;}
	  @XmlElement
	    public void setFDOB(String DOB){this.DOB = DOB;}

	  public String getGDiag() {return Diag;}
	  @XmlElement
	    public void setGDiag(String D){this.Diag = D;}

	  public String getGTreat() {return Treat;}
	  @XmlElement
	    public void setGTreat(String D){this.Treat = D;}

	  public String getGRx() {return Rx;}
	  @XmlElement
	  	public void setGRx(String D){this.Rx = D;}
	  
	  public String getTimestamp(){return Timestamp;}
	  @XmlElement
	  	public void setTimestamp(String TimeStamp) {this.Timestamp = TimeStamp;}
}

class Logger{
	/*Boiler Plate Code ---- 
	 *writes server output to the BlockchainLog.txt file*/
	private String path;
	private boolean append_to_file;

	public Logger(String fileName, boolean type){
		this.path = fileName;
		this.append_to_file = type;
	}
	public void writeToFile(String text) throws IOException{
		FileWriter write = new FileWriter(path, append_to_file);
		PrintWriter toFile = new PrintWriter(write);
		toFile.printf("%s \n\n", text);
		toFile.close();
	}
}




/*_____________________________UNVERIFIED_BLOCK_LISTENER_________________________________________*/


class unverifiedBlockListener implements Runnable{
	/*The unverifiedBlockListener object is responsible for receiving newly processed Block
	 *records and overseeing their verification prior to be written to the Blockchain. 
	 *1st) New Blocks are received and stored as XML Strings in an ArrayList
	 *2nd) The Blocks are then processed upon receiving "Verify" messages.*/
	Socket socket;
	ServerSocket serverSocket;
	Integer ProcessNum;
	static ArrayList<String> Queue = new ArrayList<String>();
	boolean listening = true;
	
	unverifiedBlockListener(ServerSocket serverSocket, Integer pnum){
		this.serverSocket = serverSocket;	
		this.ProcessNum = pnum;
	}	
	public void run() {
		ObjectInputStream in = null;
		String stringXML;
		while(listening){
			try {
				socket = serverSocket.accept(); //Connection made?
				in = new ObjectInputStream(socket.getInputStream());
				String incomingMessage = in.readObject().toString();
				
				if(incomingMessage.equals("Block")){//Store incoming block
					stringXML = in.readObject().toString();
					Queue.add(stringXML);//Add to unverified block queue
				}
				else if(incomingMessage.equals("Verify")){//Verify queued blocks
					verificationProcess(ProcessNum);
				}
				else if(incomingMessage.equals("Stop")) //Terminate the process
					listening = false;
				socket.close();
			}
				catch (Exception e) {
				e.printStackTrace();
			}
		}
	}	
	
	public static void verificationProcess(int pnum) throws Exception{
		/*This module handles the initial verification of our BlockRecord.
		 *It starts by formatting our Block strings into a single randomized array of BlockRecord objects.
		 *Each record is passed to the doWorkPuzzle() method, where the actual "work" is done before 
		 *the block is sent to be added to the chain.*/
		BlockRecord blockArray[] = new BlockRecord[Queue.size()];
		Random random = new Random();
		int currentItem;
		int i = 0;
		while(!Queue.isEmpty()){//While are blocks to be verified
			currentItem = random.nextInt((Queue.size()-1) + 1); //Randomize block order
			String xml = Queue.get(currentItem);
			Queue.remove(currentItem);
			blockArray[i] = Blockchain.reconstructBlockRecord(xml); //Reconstruct Array of BlockRecords
			i++;
		}		
		System.out.println("Doing Work...");
		for(BlockRecord unver : blockArray){//Verify each Block && solve our work puzzle
			if(!Blockchain.BlockLedger.contains(unver.getFSSNum())){ //Check for this block in the ledger
				if(unver.getAVerificationProcessID().contains("Unverified")){
					//if(verifySignedID(unver)){//Verify that the blockID was signed by the creating process
						if(doWorkPuzzle(unver)){
							BlockRecord verifiedBlock = signBlock(unver, pnum);
							sendBlock(verifiedBlock, pnum);
						//}
					}
				}
			}
		}
		System.out.println("Work Finished.");
	}
	
	@SuppressWarnings("unchecked")
	public static boolean verifySignedID(BlockRecord block) throws Exception{
		/*This module verifies the block was signed by the creating process included
		 *in the CreatingProcess field by checking the signedBlockID against the 
		 *public key associated with that process.*/
		Integer pnum = Integer.parseInt(block.getACreatingProcess());
		String blockID = block.getABlockID();
		String SignedBlockID = block.getSignedBlockID();
		PublicKey publicKey = null;
		for(Pair<Integer, PublicKey> pair : Blockchain.publicKeys){
			if(pair.getKey().equals(pnum))
				publicKey = pair.getValue();//Get the public key of the signing process
		}
		byte[] testSignature = Base64.getDecoder().decode(SignedBlockID);
		if(Blockchain.verifySignature(blockID.getBytes(), publicKey, testSignature)){
			return true;
		}
		else
			return false;
	}


	public static boolean doWorkPuzzle(BlockRecord workBlock) throws InterruptedException{
		/*This pseudo work puzzle was take from our example code. It works by repeatedly
		 *generating a random number and testing it against a specified solution.*/
	    int randval;
	    Random r = new Random();
	    for (int i=0; i<1000; i++){ //Limit of 1000 guesses
	      Thread.sleep(100);//Insert a pause to compliment our "work"
	      if(Blockchain.BlockChainReport.contains(workBlock.getABlockID()))
	    	  return false;
	      else{
	    	  randval = r.nextInt(200);//Generate a number from 0-200
	    	  if (randval < 20) {//50 is our solution value
	    		  return true;
	    	  }
	      }
	    }
	    return false;
	}
	
	public static BlockRecord signBlock(BlockRecord blockRecord, Integer pnum) throws Exception{
		/*This module finishes our verification process by inserting all of the previously
		 *excluded fields: blockNum, AVerificationProcessID, previousHash, ASHA256String, signedSHA256.
		 *The module returns to the calling process where it is sent off to be added into our Blockchain.*/
		//blockRecord.setBlockNum(Blockchain.BlockLedger.substring(Blockchain.BlockLedger.lastIndexOf("<blockNum>") + 10, Blockchain.BlockLedger.lastIndexOf("</blockNum>")));//Set the current block number
		String previousHash = Blockchain.BlockLedger.substring(Blockchain.BlockLedger.lastIndexOf("<ASHA256String>")+ 15, Blockchain.BlockLedger.lastIndexOf("</ASHA256String>"));//Get hash of previous block
		blockRecord.setPreviousHash(previousHash);
		blockRecord.setAVerificationProcessID(pnum.toString());
		String stringXML1 = Blockchain.blockToXML(blockRecord);
		String SHA256 = Blockchain.generateHash(stringXML1); //Generate block hash
		blockRecord.setASHA256String(SHA256);//Add hash to block
		String signedSHA256 = Blockchain.signHash(SHA256);//Generate signed block hash
		blockRecord.setASignedSHA256(signedSHA256);//Add signed hash to the block
		return blockRecord;
	}
	
	private static void sendBlock(BlockRecord newBlock, int ProcessNum) throws JAXBException, IOException {
		/*This module sends a verified block to the blockChainListener belonging to process 0,
		 * where the record is added to the Blockchain.*/
		Socket socket = null;
		ObjectOutputStream out = null;
		try {
			socket = new Socket(Blockchain.serverName, 4820); 
			out = new ObjectOutputStream(socket.getOutputStream());
			out.writeObject("Newly Verified Block");
			out.flush();
			out.writeObject(Blockchain.blockToXML(newBlock));
			out.flush();
			socket.close();
			}catch (IOException e) {
				e.printStackTrace();
			}
	}
	
	
}


/*_______________________________________BLOCKCHAIN_LISTENER_________________________________________________*/

class blockChainListener implements Runnable{
	/**/
	int ProcessNum;
	boolean listening = true;
	Socket socket;
	ServerSocket serverSocket;
	
	blockChainListener(ServerSocket serverSocket, Integer pnum){
		this.serverSocket = serverSocket;	
		this.ProcessNum = pnum;
	}	
	public void run() {
		ObjectInputStream in = null;
		while(listening){	
			try {
				socket = serverSocket.accept(); //Connection made?
				
				in = new ObjectInputStream(socket.getInputStream());
				String incomingMessage = in.readObject().toString();
				
				if(incomingMessage.equals("start")){
					startProcess(ProcessNum);
				}
				else if(incomingMessage.equals("Newly Verified Block")){//Verified blocks to be added to the chain
					BlockRecord newBlock = Blockchain.reconstructBlockRecord(in.readObject().toString());
					AddToChain(newBlock, ProcessNum);
				}
				else if(incomingMessage.equals("Blockchain")){//Updated Blockchain transmission
					Blockchain.BlockLedger = in.readObject().toString();
					Blockchain.BlockChainReport = in.readObject().toString();
				}
				else if(incomingMessage.equals("Key")){//Public keys, transmitted upon initialization of each process
					Integer processNum = Integer.parseInt(in.readObject().toString());//Receive process number associated with incoming key
					byte[] len = new byte[4];
					in.read(len,0,4);
			        ByteBuffer keyBuf = ByteBuffer.wrap(len);
			        int length = keyBuf.getInt();
			        byte[] keyBytes = new byte[length];
			        in.read(keyBytes);
					PublicKey publicKey = reCreateKey(keyBytes);
					Pair<Integer, PublicKey> newKey = new Pair<Integer, PublicKey>(processNum, publicKey);
					if(!Blockchain.publicKeys.contains(newKey))
						Blockchain.publicKeys.add(newKey);
				}
				else if(incomingMessage.equals("Stop"))
					listening = false;
				socket.close();
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}
	
	public static void startProcess(int ProcessNum) throws Exception {
		Blockchain.multicastKey();
		Blockchain.blockRecordGenerator(ProcessNum, Blockchain.FileList[ProcessNum]); // START PROCESSING BLOCK
		
	}
	public void AddToChain(BlockRecord newBlock, Integer ProcessNum) throws Exception{
		if(Blockchain.BlockLedger.contains(newBlock.getFSSNum()))
			return;
		else
			Blockchain.addToLedger(newBlock);
	}

	public static PublicKey reCreateKey(byte[] myKey) throws NoSuchAlgorithmException, InvalidKeySpecException{
		 X509EncodedKeySpec myKey2 = new X509EncodedKeySpec(myKey);
		 KeyFactory kf = KeyFactory.getInstance("RSA");
         PublicKey publicKey = kf.generatePublic(myKey2);
		return publicKey;
	}
}

/*____________________________________BLOCKCHAIN_____________________________________________*/


public class Blockchain {
	static Logger fileLog = new Logger("BlockchainLog.txt", true);//Logging Module
	static Logger fileLog2 = new Logger("BlockchainLedger.xml", false);
	static String FileList[] = {"BlockInput0.txt", "BlockInput1.txt", "BlockInput2.txt"};
	//Internal Blockchain Storage;
	static String BlockLedger = "";
	static String BlockChainReport;
	static Integer numberOfBlocks = 0;
	static ArrayList<BlockRecord> BlockRecords = new ArrayList<BlockRecord>();
	//Server Socket Information
	static String serverName = "localhost";//Hostname/IP
	static int UnverifiedBlockPort = 4710;//Default port for unverified blocks
	static int BlockChainPort = 4820;//Default port for Blockchains
	static ServerSocket unverifiedSocket;
	static ServerSocket blockchainSocket;
	static Integer ProcessNum;
	//Server Key Storage
	static PrivateKey privateKey;
	static PublicKey publicKey;
	@SuppressWarnings("rawtypes")
	static ArrayList<Pair> publicKeys = new ArrayList<Pair>();
	
	/* Token indexes, used to format BlockRecord input file information*/
	private static final int iFNAME = 0;
	private static final int iLNAME = 1;
	private static final int iDOB = 2;
	private static final int iSSNUM = 3;
	private static final int iDIAG = 4;
	private static final int iTREAT = 5;
	private static final int iRX = 6;
	
	public static void main(String args[]) throws Exception{
		if(args[0] == null)
			ProcessNum = 0;
		else
			ProcessNum = Integer.parseInt(args[0]);
		
		String processTime ="Process Timestamp:" + generateTimestamp(ProcessNum);
		fileLog.writeToFile(processTime);
		System.out.println(processTime);
		
		/*Display & Log Process Header*/
		String processHeader = "Process number " + ProcessNum + ", Ports: " + (UnverifiedBlockPort + ProcessNum) + " " + 
		       (BlockChainPort + ProcessNum) + "\n";//Process details header
		System.out.println(processHeader);
		fileLog.writeToFile(processHeader); //Write to BlockchainLog

		/*Generate private-public key pair*/
		keyPairGenerator();
		
		createDummyBlock();//Create initial Blockchain block
		createBlockReport();
		
		/*Start process listeners*/
		unverifiedSocket = new ServerSocket(UnverifiedBlockPort+ProcessNum);
		blockchainSocket = new ServerSocket(BlockChainPort+ProcessNum);
		Runnable r1 = new unverifiedBlockListener(unverifiedSocket, ProcessNum);
		Runnable r2 = new blockChainListener(blockchainSocket, ProcessNum);
		new Thread (r1).start();
		new Thread (r2).start();
		
		/*__________________Console_Command______________________________*/
		String options = "\nAvailable Commands: "
				+ "\n   R [filename] - Process new record file"
				+ "\n   V            - Generate Blockchain verification report"
				+ "\n   L            - List each Block in the Blockchain" 
				+ "\n   P            - Display the Blockchain in XML\n\nType 'quit' to Exit.\n\n";
		System.out.println(options);
		
		if(ProcessNum == 2){//Start Blockhain after Process 2 is created and commands are displayed.
			fileLog.writeToFile(options);//Write option display to the console log a single time
			multicastStart();//Signal our processes to start
		}
		
		String userEntry = "0";
		Scanner scanner = new Scanner(System.in);
		do { 
			userEntry = scanner.nextLine();
			if(userEntry.equals(null) || userEntry.equals(""))
				continue;
			else if(userEntry.charAt(0) == 'R'){
				if(!userEntry.contains(".txt"))
					System.out.println("Incorrect File Format!");
				else{
					String newFile = userEntry.substring(2, userEntry.indexOf("."));
					blockRecordGenerator(ProcessNum, newFile + ".txt");
				}
			}
			else if(userEntry.equals("V"))//Verify Blockchain and return a summary
				getBlockchainReport();
			else if(userEntry.equals("L")){//Return A list of current records
				fileLog.writeToFile(BlockChainReport);
				System.out.println(BlockChainReport);
			}
			else if(userEntry.equals("P")){
				System.out.println(BlockLedger);
			}
		}while(userEntry.toLowerCase().equals("quit") != true);
		scanner.close();
		multicastStop();
	}
	
	
	/*Multicast_Functions*/
	public static void multicastStart() throws Exception{
		/*This module signals each process to begin sending their input files 
		 *by sending a start message to the blockchainListener's of each 
		 *available process, which triggers initial block processing. 
		 **/
		Socket socket;
		ObjectOutputStream toServer;
		for(int i = 0; i < 3; i++){
			socket = new Socket(serverName, BlockChainPort + i);//Open Communication Channel
			toServer = new ObjectOutputStream(socket.getOutputStream());
			toServer.writeObject("start"); //Send start message
			toServer.flush();
			socket.close();
		}
	}
	public static void multicastStop(){
		/*This module is designed to stop all running processes upon receiving 
		 *the 'quit' entry at the console. It sends a "Stop" message to both listeners
		 *for each process in the current program.*/
		Socket socket1;
		Socket socket2;
		ObjectOutputStream toServer;
		for(int i = 0; i < 3; i++){
			try {
				socket1 = new Socket("localhost", BlockChainPort + i);
				toServer = new ObjectOutputStream(socket1.getOutputStream());//Connect to BlockchainListener
				toServer.writeObject("Stop"); //Send stop message
				toServer.flush();
				socket1.close();
				socket2 = new Socket("localhost", UnverifiedBlockPort + i);
				toServer = new ObjectOutputStream(socket2.getOutputStream());//Connect to unverifiedBlockListener
				toServer.writeObject("Stop"); //Send stop message
				toServer.flush();
				socket2.close();
				if(ProcessNum == 0){
					System.out.println("Process " + i + " has been terminated.");
					fileLog.writeToFile("Process " + i + " has been terminated.");
				}
			} catch (IOException e) {
				System.out.println("Exiting...");
			}
		}
	}
	
	public static void multicastBlock(String blockArray){
		/*This iteration of the multicast function is designed to transmit unverified blocks
		 *to the UnverifiedBlockListeners of each process for subsequent work & verification.*/
		Socket socket = null;
		ObjectOutputStream out = null;
		for(int pnum = 0; pnum < 3; pnum++){
			try {
				socket = new Socket(serverName, UnverifiedBlockPort + pnum);
				out = new ObjectOutputStream(socket.getOutputStream());
				out.writeObject("Block");
				out.flush();
				out.writeObject(blockArray);
				out.flush();
				socket.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}
	
	public static void multicastChain(){
		/*This iteration of the multicast function is designed to push the updated Blockchain representation
		 *to each process and their respective server. In addition, a report associated with the updated 
		 *Blockchain is sent.*/
		Socket socket = null;
		ObjectOutputStream out = null;
		for(int pnum = 0; pnum < 3; pnum++){
			try {
				socket = new Socket(serverName, BlockChainPort + pnum); 
				out = new ObjectOutputStream(socket.getOutputStream());
				out.writeObject("Blockchain");
				out.flush();
				out.writeObject(BlockLedger);//Send the ledger
				out.flush();
				out.writeObject(BlockChainReport);//Send the verification report
				out.flush();
				socket.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}
	
	public static void multicastKey(){
		/*This iteration of the multicast function transmits the PublicKey associated with the sender
		 *to each member process.*/
		Socket socket = null;
		ObjectOutputStream out = null;
		ByteBuffer keyBuf = null;
		for(int pnum = 0; pnum < 3; pnum++){
			try {
				socket = new Socket(serverName, BlockChainPort + pnum);
				out = new ObjectOutputStream(socket.getOutputStream());
				out.writeObject("Key");
				out.flush();
				out.writeObject(ProcessNum.toString());
				out.flush();
				keyBuf = ByteBuffer.allocate(4);
		        keyBuf.putInt(publicKey.getEncoded().length);
		        out.write(keyBuf.array());
		        out.write(publicKey.getEncoded());
		        out.flush();
				socket.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}	
	}
	
	
	/*_________________________BlockEditor_Functions______________________*/
	
	
	public static void blockRecordGenerator(Integer pnum, String FILENAME) throws Exception{
		BufferedReader br = new BufferedReader(new FileReader(FILENAME));
		/*This function generates our unverified block based on a given Input File*/		
		String[] tokens = new String[10];
		String InputLineStr;
		String suuid; //UUID signed by the creating process
		UUID idA;//The universally unique ID
		JAXBContext jaxbContext = JAXBContext.newInstance(BlockRecord.class);
		Marshaller jaxbMarshaller = jaxbContext.createMarshaller();
		jaxbMarshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
		int n = 0;
		
		while ((InputLineStr = br.readLine()) != null) {
			BlockRecord blockArray = new BlockRecord();//create block record object
			blockArray.setASHA256String("TBD");
			blockArray.setASignedSHA256("TBD");
			blockArray.setAVerificationProcessID("Unverified");
			blockArray.setPreviousHash("TBD");
			blockArray.setSeed("xx");
			blockArray.setBlockNum("TBD");
			idA = UUID.randomUUID();//generate random UUID
			blockArray.setABlockID(idA.toString());//signData(suuid, privateKey).toString());
			suuid = Base64.getEncoder().encodeToString(signData(idA.toString().getBytes(), privateKey));
			blockArray.setSignedBlockID(suuid);
			
			blockArray.setACreatingProcess(Integer.toString(pnum));
			blockArray.setDataHash(generateHash(InputLineStr));
			
			/* Set BlockRecord File Fields */
			tokens = InputLineStr.split(" +"); // Tokenize the input
			blockArray.setFSSNum(tokens[iSSNUM]);
			blockArray.setFFname(tokens[iFNAME]);
			blockArray.setFLname(tokens[iLNAME]);
			blockArray.setFDOB(tokens[iDOB]);
			blockArray.setGDiag(tokens[iDIAG]);
			blockArray.setGTreat(tokens[iTREAT]);
			blockArray.setGRx(tokens[iRX]);
			blockArray.setTimestamp(generateTimestamp(pnum));
			String newBlock = blockToXML(blockArray);
			multicastBlock(newBlock);
			n++;
		}
		String inputHeader = "Process " + pnum + ", Using input file: " + FILENAME + "\n" + n + " records processed"; //Display input file name
		System.out.println(inputHeader);
		fileLog.writeToFile(inputHeader); //Write to BlockchainLog
		
		Socket socket;
		ObjectOutputStream toServer;
		socket = new Socket(serverName, 4710 + pnum);
		toServer = new ObjectOutputStream(socket.getOutputStream());
		toServer.writeObject("Verify"); //Send start message
		toServer.flush();
		socket.close();
	}
	
	public static void addToLedger(BlockRecord blockRecord) throws Exception{
		/*This module is designed to append verified blocks to the Blockchain.
		 *It begins with a series of checks aimed at thwarting the insertion
		 *of duplicate blocks.*/
		if(BlockLedger.contains(blockRecord.getABlockID()))
			return;
		else if(BlockLedger.contains(blockRecord.getASHA256String()))
			return;
		else{
			Integer blockNum = Integer.parseInt(BlockLedger.substring(BlockLedger.lastIndexOf("<blockNum>") + 10, BlockLedger.lastIndexOf("</blockNum>")))+1;
			blockRecord.setBlockNum(blockNum.toString());
			String stringXML = blockToXML(blockRecord);
			String XMLHeader = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>";
			BlockLedger = BlockLedger.replace("<BlockLedger>\n", "");
			BlockLedger = BlockLedger.replace("<BlockLedger>", "");
			BlockLedger = BlockLedger.replace("</BlockLedger>", "");
			BlockLedger = BlockLedger.replace(XMLHeader, "");
			stringXML = stringXML.replace("<BlockLedger>", "");
			stringXML = stringXML.replace("</BlockLedger>", "");
			stringXML = stringXML.replace(XMLHeader, "");
			String XMLBlock = XMLHeader + "\n<BlockLedger>" + BlockLedger + stringXML + "</BlockLedger>";
			fileLog2.writeToFile(XMLBlock);
			BlockLedger = XMLBlock;
			if(!BlockRecords.contains(blockRecord))
				BlockRecords.add(blockRecord);//Add to record for report generation
			createBlockReport();//Update Blockchain Report
			multicastChain();
			Thread.sleep(100);
		}
	}
	
	public static void writeLedger(String newBlock) throws IOException{
		/*This method writes the input Block to the BlockChain. It concatenates 
		 *new Blocks to the end of the chain by performing some string manipulation
		 *to reformat the oldBlock and newBlock into XML compliant String data.*/
		String XMLHeader = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>";
		String oldBlock = BlockLedger;
		oldBlock.replace("<BlockLedger>", "");
		oldBlock.replace("</BlockLedger>", "");
		String cleanBlock = newBlock.replace(XMLHeader, "");
		cleanBlock.replace("<BlockLedger>", "");
		cleanBlock.replace("</BlockLedger>", "");
		String newXMLBlock = "<BlockLedger>" + oldBlock + newBlock + "</BlockLedger>";
		fileLog2.writeToFile(newXMLBlock);
		BlockLedger = newXMLBlock;
	}

	public static String blockToXML(BlockRecord blockRecord) throws JAXBException{
		/*This bit of code converts our BlockRecord Objects into XML formatted strings
		 *that can be sent across a network.*/
	    JAXBContext jaxbContext = JAXBContext.newInstance(BlockRecord.class);
	    Marshaller jaxbMarshaller = jaxbContext.createMarshaller();
	    StringWriter sw = new StringWriter();
	    jaxbMarshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
	    jaxbMarshaller.marshal(blockRecord, sw);
	    return sw.toString();
	}

	public static void createDummyBlock() throws Exception{
		/*This module creates the initial generic Block for our BlockChain upon the initialization of
		 *process number 2.*/
		BlockRecord initialBlock = new BlockRecord();
		String X = "Init";
		initialBlock.setAVerificationProcessID("Init");
		initialBlock.setPreviousHash("0000");
		initialBlock.setSeed("xx");
		initialBlock.setBlockNum("0");
		initialBlock.setABlockID("0");
		initialBlock.setSignedBlockID("0");
		initialBlock.setACreatingProcess("Init");
		initialBlock.setDataHash("0000");
		initialBlock.setFSSNum(X);
		initialBlock.setFFname(X);
		initialBlock.setFLname(X);
		initialBlock.setFDOB(X);
		initialBlock.setGDiag(X);
		initialBlock.setGTreat(X);
		initialBlock.setGRx(X);
		initialBlock.setTimestamp("0:0:0:0");
		
		initialBlock.setASHA256String(generateHash(blockToXML(initialBlock)));
		initialBlock.setASignedSHA256("0000");
		BlockRecords.add(initialBlock);
		String xmlDummy = blockToXML(initialBlock);
		writeLedger(xmlDummy);
	}
	
	
	
	/*__________________________HASHING_FUNCTIONS_______________________________*/
	
	
	
	public static void keyPairGenerator() throws NoSuchAlgorithmException{
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");//Generator for RSA key pair
		generator.initialize(2048);//Key size of 2048
		KeyPair pair = generator.generateKeyPair();//Generate key pair
		privateKey = pair.getPrivate();//Assign private key
		publicKey = pair.getPublic();//Assign public key
		publicKeys.add(new Pair<Integer, PublicKey>(ProcessNum, publicKey));//Add public key-Process Number pair to internal public key storage
	}
	
	
	public static byte[] signData(byte[] data, PrivateKey key) throws Exception {
		Signature signer = Signature.getInstance("SHA1withRSA");
		signer.initSign(key);
		signer.update(data);
		return (signer.sign());
	}

	public static boolean verifySignature(byte[] data, PublicKey key, byte[] sig) throws Exception {
		Signature signer = Signature.getInstance("SHA1withRSA");
		signer.initVerify(key);
		signer.update(data);
		return (signer.verify(sig));
  }
	
	public static String generateHash(String inputBlock) throws NoSuchAlgorithmException{
		/*This function takes a single record as input and returns the Hash to be 
		 *included in the associated BlockRecord object. 
		 *The hashing algorithm used is: SHA-256.
		 * */
		MessageDigest md = MessageDigest.getInstance("SHA-256"); //Create Message Digest
	    md.update (inputBlock.getBytes());//Queue input data to be hashed
	    byte byteData[] = md.digest();//Complete hashing sequence.
	    StringBuffer sb = new StringBuffer();
	    for (int i = 0; i < byteData.length; i++) {//Convert Byte Array to hexadecimal.
	    	sb.append(Integer.toString((byteData[i] & 0xff) + 0x100, 16).substring(1));
	     } 
	    String hash = sb.toString();
		return hash;
	}
	
	public static String signHash(String hash) throws Exception{
		/*This function returns the hash after it has been signed with the private key
		 *associated with the process.*/
		byte[] digitalSignature = signData(hash.getBytes(), privateKey);
		String signedHash = Base64.getEncoder().encodeToString(digitalSignature);
		return signedHash;
	}
	
	
	
	
	/*_________________________________FINISHED_FUNCTIONS______________________________________*/	
	
	
	public static void getBlockchainReport() throws Exception{
		/*This module produces a variation of the Blockchain verification request.
		 *This particular implementation merely records and displays; the number of blocks that 
		 *have been verified in the Blockchain, and the number of blocks each process is responsible
		 *for verifying.*/
		int pnum0 = 0, pnum1 = 0, pnum2 = 0, blockNum = -1;
		Pattern p0 = Pattern.compile(" <AVerificationProcessID>0");
		Pattern p1 = Pattern.compile(" <AVerificationProcessID>1");
		Pattern p2 = Pattern.compile(" <AVerificationProcessID>2");
		Pattern unver = Pattern.compile("Unverified");
		Pattern block = Pattern.compile("<blockRecord>");
		Matcher m0 = p0.matcher(BlockLedger);
		Matcher m1 = p1.matcher(BlockLedger);
		Matcher m2 = p2.matcher(BlockLedger);
		Matcher unv = unver.matcher(BlockLedger);
		Matcher num = block.matcher(BlockLedger);

		while(m0.find()){
			pnum0++;
		}
		while(m1.find()){
			pnum1++;
		}
		while(m2.find()){
			pnum2++;
		}
		while(num.find()){
			blockNum++;
		}
		while(unv.find()){
			blockNum--;
		}
		blockNum = verifyBlockHash(blockNum); //Verify the digitalSignature of each block to detect forgery
		String report = "--" + blockNum + " Blocks in the Blockchain have been verified. Credit: P0=" + pnum0 + " P1=" + pnum1 + " P2=" + pnum2;
		fileLog.writeToFile(report);
		System.out.println(report);
	}
	@SuppressWarnings("unchecked")
	public static int verifyBlockHash(int blockNum) throws Exception{
		/*This module is designed to verify the hash belonging to each verified block in the Blockchain.
		 *The signedSHA256 hash belonging to the block is checked against the publicKey of the process
		 *that originally generated each of the block's associated hashes. The Block Number of any blocks 
		 *that fail the verification test are displayed and the number of verified blocks is returned.*/
		for(BlockRecord block : BlockRecords){//Test each block in the ledger.
			if(block.getAVerificationProcessID().equals("Init")){//Detect initial block
				continue;
			}
			Integer pnum = Integer.parseInt(block.getAVerificationProcessID());
			PublicKey publicKey = null;
			for(Pair<Integer, PublicKey> pair : publicKeys){
				if(pair.getKey().equals(pnum))
					publicKey = pair.getValue();//Get the public key of the signing process
			}
			String SHA256String = block.getASHA256String();
			String SignedSHA256 = block.getASignedSHA256();
			byte[] testSignature = Base64.getDecoder().decode(SignedSHA256);
			if(!verifySignature(SHA256String.getBytes(), publicKey, testSignature)){//Test the Hash/Key
				System.out.println("Block Number " + block.getBlockNum() + " is unverified.");
				blockNum--;
			}
		}
		return blockNum;//Return the number of successful verifications
	}
	
	public static void createBlockReport(){
		/*This module generates a report of all records currently in the Blockchain.*/
		BlockRecord currentBlock;
		String tempChain = "";
		for(int i = BlockRecords.size(); i > 0; i--){
			currentBlock = BlockRecords.get(i-1);
			tempChain += ((i - 1) + ". " + currentBlock.getTimestamp() + " " + currentBlock.getFFname() + " " + currentBlock.getFLname() + " " +
								currentBlock.getFDOB() + " " + currentBlock.getFSSNum() + " " + currentBlock.getGDiag() + " " + currentBlock.getGTreat() + 
								" " + currentBlock.getGRx() + "\n");
		}
		BlockChainReport = tempChain;
	}
	
	public static BlockRecord reconstructBlockRecord(String Block){
		/*This module converts Block Records sent over our socket from an XML string back into a BlockRecord object.
		 *---There are two rounds of string processing that help accurately extract our parameters. The subsequent 
		 *redundancy was an inelegant result of troubleshooting the process, which I will seek to simplify in the future.*/
		BlockRecord Blockrecord = new BlockRecord();
		Blockrecord.setASHA256String(Block.substring(Block.indexOf("<ASHA256String>") + 1, Block.indexOf("</ASHA256String>")));
		Blockrecord.setASignedSHA256(Block.substring(Block.indexOf("<ASignedSHA256>") + 1, Block.indexOf("</ASignedSHA256>")));
		Blockrecord.setAVerificationProcessID(Block.substring(Block.indexOf("<AVerificationProcessID>") + 1, Block.indexOf("</AVerificationProcessID>")));
		Blockrecord.setPreviousHash(Block.substring(Block.indexOf("<previousHash>") + 1, Block.indexOf("</previousHash>")));
		Blockrecord.setSeed(Block.substring(Block.indexOf("<seed>") + 1, Block.indexOf("</seed>")));
		Blockrecord.setBlockNum(Block.substring(Block.indexOf("<blockNum>") + 1, Block.indexOf("</blockNum>")));
		Blockrecord.setABlockID(Block.substring(Block.indexOf("<ABlockID>") + 1, Block.indexOf("</ABlockID>")));
		Blockrecord.setSignedBlockID(Block.substring(Block.indexOf("<signedBlockID>") + 1, Block.indexOf("</signedBlockID>")));
		Blockrecord.setACreatingProcess(Block.substring(Block.indexOf("<ACreatingProcess>") + 1, Block.indexOf("</ACreatingProcess>")));
		Blockrecord.setFDOB(Block.substring(Block.indexOf("<FDOB>") + 1, Block.indexOf("</FDOB>")));
		Blockrecord.setFFname(Block.substring(Block.indexOf("<FFname>") + 1, Block.indexOf("</FFname>")));
		Blockrecord.setFLname(Block.substring(Block.indexOf("<FLname>") + 1, Block.indexOf("</FLname>")));
		Blockrecord.setFSSNum(Block.substring(Block.indexOf("<FSSNum>") + 1, Block.indexOf("</FSSNum>")));
		Blockrecord.setGDiag(Block.substring(Block.indexOf("<GDiag>") + 1, Block.indexOf("</GDiag>")));
		Blockrecord.setGRx(Block.substring(Block.indexOf("<GRx>") + 1, Block.indexOf("</GRx>")));
		Blockrecord.setGTreat(Block.substring(Block.indexOf("<GTreat>") + 1, Block.indexOf("</GTreat>")));
		Blockrecord.setTimestamp(Block.substring(Block.indexOf("<timestamp>") + 1, Block.indexOf("</timestamp>")));
		/*___________________________________________________________________________________________*/
		Blockrecord.setASHA256String(Blockrecord.getASHA256String().substring(Blockrecord.getASHA256String().indexOf(">") + 1));
		Blockrecord.setASignedSHA256(Blockrecord.getASignedSHA256().substring(Blockrecord.getASignedSHA256().indexOf(">") + 1));
		Blockrecord.setAVerificationProcessID(Blockrecord.getAVerificationProcessID().substring(Blockrecord.getAVerificationProcessID().indexOf(">") + 1));
		Blockrecord.setPreviousHash(Blockrecord.getPreviousHash().substring(Blockrecord.getPreviousHash().indexOf(">") + 1));
		Blockrecord.setSeed(Blockrecord.getSeed().substring(Blockrecord.getSeed().indexOf(">") + 1));
		Blockrecord.setBlockNum(Blockrecord.getBlockNum().substring(Blockrecord.getBlockNum().indexOf(">") + 1));
		Blockrecord.setABlockID(Blockrecord.getABlockID().substring(Blockrecord.getABlockID().indexOf(">") + 1));
		Blockrecord.setSignedBlockID(Blockrecord.getSignedBlockID().substring(Blockrecord.getSignedBlockID().indexOf(">") + 1));
		Blockrecord.setACreatingProcess(Blockrecord.getACreatingProcess().substring(Blockrecord.getACreatingProcess().indexOf(">") + 1));
		Blockrecord.setFDOB(Blockrecord.getFDOB().substring(Blockrecord.getFDOB().indexOf(">") + 1));
		Blockrecord.setFFname(Blockrecord.getFFname().substring(Blockrecord.getFFname().indexOf(">") + 1));
		Blockrecord.setFLname(Blockrecord.getFLname().substring(Blockrecord.getFLname().indexOf(">") + 1));
		Blockrecord.setFSSNum(Blockrecord.getFSSNum().substring(Blockrecord.getFSSNum().indexOf(">") + 1));
		Blockrecord.setGDiag(Blockrecord.getGDiag().substring(Blockrecord.getGDiag().indexOf(">") + 1));
		Blockrecord.setGRx(Blockrecord.getGRx().substring(Blockrecord.getGRx().indexOf(">") + 1));
		Blockrecord.setGTreat(Blockrecord.getGTreat().substring(Blockrecord.getGTreat().indexOf(">") + 1));
		Blockrecord.setTimestamp(Blockrecord.getTimestamp().substring(Blockrecord.getTimestamp().indexOf(">") + 1));
		return Blockrecord;
	}	
	public static String generateTimestamp(int pnum){
	    Date date = new Date();
	    String T1 = String.format("%1$s %2$tF.%2$tT", "", date);
	    String TimeStampString = T1 + "." + pnum;
	    return TimeStampString;
	}
}