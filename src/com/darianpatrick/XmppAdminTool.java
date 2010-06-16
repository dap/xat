package com.darianpatrick;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.TreeMap;
import java.util.Map.Entry;

import nanoxml.XMLElement;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.cli.PosixParser;
import org.jivesoftware.smack.ConnectionConfiguration;
import org.jivesoftware.smack.PacketCollector;
import org.jivesoftware.smack.XMPPConnection;
import org.jivesoftware.smack.XMPPException;
import org.jivesoftware.smack.filter.PacketIDFilter;
import org.jivesoftware.smack.packet.IQ;
import org.jivesoftware.smackx.Form;
import org.jivesoftware.smackx.FormField;
import org.jivesoftware.smackx.commands.AdHocCommandManager;
import org.jivesoftware.smackx.commands.RemoteCommand;
import org.jivesoftware.smackx.packet.DiscoverItems;
import org.jivesoftware.smackx.packet.Version;

public class XmppAdminTool {

	private static final String     DEFAULT_RESOURCE = "XmppAdminTool";
	private static final Integer    DEFAULT_PORT = 5222;
	private AdHocCommandManager     commandManager;
	private ConnectionConfiguration conf;
	private XMPPConnection          connection;
	private Options                 opts;
	private boolean                 displayVerboseMessages = false;
	private boolean                 displayDebugMessages = false;

	public XmppAdminTool() {
		setCliOpts();
	}

	private void setCliOpts () {
		opts = new Options();
		opts.addOption( "h", "help", false, "Display this message");
		opts.addOption( "H", "hostname", true, "Hostname of server");

		opts.addOption( "c", "command-jid",
				true,  "Command JID (usually realm portion of user JID when" +
						" requesting server info");
		opts.addOption( "u", "username",
				true,  "Username");
		opts.addOption( "p", "password",
				true,  "Password; supply '-' to prompt for password");
		opts.addOption( "o", "port",
				true,  "Port");
		opts.addOption( "r", "resource",
				true,  "Resource");
		opts.addOption( "v", "verbose",
				false, "Show verbose messages");
		opts.addOption( "d", "debug",
				false, "Show debugging messages");

		// Command opts
		opts.addOption( "T", "timeout",
				true, "Seconds to wait for response from client [default 10]");
		opts.addOption( "C", "display-commands",
				false, "Display commands available on server");
		opts.addOption( "J", "display-active-users",
				false, "Display jids of active users");
		opts.addOption( "O", "display-num-online-users",
				false, "Display number of online users");
		opts.addOption( "A", "display-num-active-users",
				false, "Display number of active users");
		opts.addOption( "S", "display-num-connected-sessions",
				false, "Display number of connected sessions");
		opts.addOption( "K", "display-clients",
				false, "Display clients in use");
		opts.addOption( "P", "truststore-path",
				true, "Path to truststore containing CA cert(s)");
		opts.addOption( "Y", "truststore-type",
				true, "Truststore type (GKR, jks, etc.)");
		opts.addOption( "Z", "display-server-stats",
				false, "Display server statistics");
	}

	private void connect(String username, String password, String resource) {
		try {
			connection = new XMPPConnection(conf);
			connection.connect();
			// TODO SaslException is thrown here - figure out how to catch it
			connection.login(username, password, resource);
		}
		catch (Exception e) {
			System.out.println("Error connecting as "
					+ username +"; check credentials.");
			if ( displayDebugMessages ) {
				System.out.print(e.getMessage());
			}
			System.exit(1);
		}
		commandManager
			= AdHocCommandManager.getAddHocCommandsManager(connection);
	}

	private void disconnect() {
		connection.disconnect();
	}

	@SuppressWarnings("unused")
	private void printResponseForm ( Form response ) {
		try {
			List<String> command = new ArrayList<String>();
			command.add("xmllint");
			command.add("--format");
			command.add("--recover");
			command.add("-");
			for(Iterator<FormField> it = response.getFields(); it.hasNext(); ) {
				FormField field = it.next();
				ProcessBuilder pb = new ProcessBuilder(command);
				final Process process = pb.start();
				OutputStream os = process.getOutputStream();
				OutputStreamWriter osw = new OutputStreamWriter(os);
				osw.write(field.toXML());
				osw.close();
				InputStream is = process.getInputStream();
				InputStreamReader isr = new InputStreamReader(is);
				BufferedReader br = new BufferedReader(isr);
				String line;
				while ((line = br.readLine()) != null)
				{
					System.out.println(line);
				}
			}
		}
		catch (IOException e) {
			e.printStackTrace();
		}
	}

	private Object callSingleResponseCommand (
			String command_jid, String command, String response_param) {
		try {
			RemoteCommand cmd
				= commandManager.getRemoteCommand(command_jid, command);
			cmd.execute();
			Form response = cmd.getForm();
			
			if ( !cmd.getStatus().toString().equals("completed") ) {
				return null;
			}
			return response.getField(response_param).getValues().next();
		}
		catch (Exception ex) {
			ex.printStackTrace();
		}
		return null;
	}

	@SuppressWarnings("unused")
	public void printSupportedCommands (String command_jid) {
		DiscoverItems cmds;
		try {
			cmds = commandManager.discoverCommands(command_jid);
			if ( cmds.getItems().hasNext() ) {
				for (Iterator<DiscoverItems.Item> it = cmds.getItems();
															it.hasNext();) {
					DiscoverItems.Item item = (DiscoverItems.Item) it.next();
					System.out.println(
						item.getName() + "\n\t" + item.getNode());
				}
			}
			else {
				System.out.println("No commands available at " + command_jid);
			}
		}
		catch (XMPPException xe) {
			System.out.println(
					"Error retrieving available commands for " + command_jid
						+ ": " + xe.getLocalizedMessage());
			System.exit(1);
		}
	}
	
	public ArrayList<String> getActiveUsers (String command_jid) {
		ArrayList<String> activeUsers = new ArrayList<String>();

		try {
			RemoteCommand cmd = commandManager.getRemoteCommand(command_jid,
					"http://jabber.org/protocol/admin#get-active-users");
			cmd.execute();
			Form response1 = cmd.getForm();
			
			if ( !response1.getType().toString().equals("form") ) {
				/*System.out.println(
						"Unhandled error while retrieving active users for "
								+ jid + " from " + SERVER + ".");*/
				return null;
			}

			Form form = response1.createAnswerForm();
			ArrayList<String> max_items = new ArrayList<String>();
			max_items.add("200");
			form.setAnswer("max_items", max_items);
			try {
				cmd.complete(form);
				Form response2 = cmd.getForm();
				Iterator<String> response2Values
					= response2.getField("activeuserjids").getValues();

				if ( !response2Values.hasNext() ) {
					return null;
				}
				
				while ( response2Values.hasNext() ) {
					activeUsers.add(response2Values.next());
					/*System.out.println(
						activeUsers.get(activeUsers.size() -1) );*/
				}
			}
			catch (XMPPException xe) {
				xe.printStackTrace();
			}
		}
		catch (Exception ex) {
			ex.printStackTrace();
		}

		return activeUsers;
	}

	public ArrayList<String> getActiveUserResources (String command_jid) {
		ArrayList<String> activeUserResources = new ArrayList<String>();
		try {
			RemoteCommand cmd = commandManager.getRemoteCommand(command_jid,
					"http://jabber.org/protocol/admin#get-active-presences");
			cmd.execute();
			Form response1 = cmd.getForm();
			
			if ( !response1.getType().toString().equals("form") ) {
				System.out.println(
					"Unhandled error while retrieving active user" +
					" resources for " + command_jid + ".");
				return null;
			}

			Form form = response1.createAnswerForm();
			ArrayList<String> max_items = new ArrayList<String>();
			max_items.add("200");
			form.setAnswer("max_items", max_items);
			try {
				cmd.complete(form);
				Form response2 = cmd.getForm();
				Iterator<String> response2Values
					= response2.getField("activeuserpresences").getValues();

				if ( !response2Values.hasNext() ) {
					return null;
				}
				
				XMLElement xml = new XMLElement();
				while ( response2Values.hasNext() ) {
					xml.parseString( response2Values.next() );
					activeUserResources.add(
						xml.getAttribute("from").toString()
					);
				}
			}
			catch (XMPPException xe) {
				xe.printStackTrace();
			}
		}
		catch (Exception ex) {
			ex.printStackTrace();
		}

		return activeUserResources;
	}
	
	public Version getClientVersion (String jid, Integer timeout) {
		Version version = new Version();
		version.setType(IQ.Type.GET);
		version.setTo(jid);

		// Create a packet collector to listen for a response.
		PacketCollector collector
			= connection.createPacketCollector(
					new PacketIDFilter( version.getPacketID() ) );

		connection.sendPacket(version);

		// Wait for result up to timeout*1000 milliseconds
		IQ result = (IQ)collector.nextResult(timeout*1000);
		// Close the collector
		collector.cancel();

		// If the client did not report its name
		if ( result == null || !(result.getType() == IQ.Type.RESULT)
				|| ((Version) result).getName().isEmpty() ) {
			// Attempt to divine client from resource setting
			if (       jid.contains("IM+")
					|| jid.contains("JiveTalk")
					|| jid.contains("Kopete")
					|| jid.contains("Meebo")
					|| jid.contains("Pandion")
					|| jid.contains("Pidgin") )
			{
				result = (IQ) new Version();
				result.setType(IQ.Type.RESULT );
				result.setFrom(jid);
				result.setTo( connection.getUser() );

				if      ( jid.contains("IM+") )
					((Version) result).setName("IM+");
				else if ( jid.contains("JiveTalk") )
					((Version) result).setName("JiveTalk");
				else if ( jid.contains("Kopete") )
					((Version) result).setName("Kopete");
				else if ( jid.contains("Meebo") )
					((Version) result).setName("Meebo");
				else if ( jid.contains("Pandion") )
					((Version) result).setName("Pandion");
				else
					((Version) result).setName("Pidgin");

				if (displayVerboseMessages)
					System.out.println(
						"Setting fake response to client/version query for "
							+ jid + " derived from resource");
				return (Version) result;
			}

			// Otherwise bail out and return null
			if (displayVerboseMessages)
				System.out.println(
					"Could not retrieve client/version for " + jid);
			return null;
		}

		return (Version) result;
	}
	
	public void printClientVersions (String command_jid, Integer timeout)
	{
		HashMap<String, Integer> actualClientCounts
			= new HashMap<String, Integer>();
		TreeMap<String, Integer> collapsedClientCounts
			= new TreeMap<String, Integer>();
		TreeMap<String, String[]> clientsByJid
			= new TreeMap<String, String[]>();

		collapsedClientCounts.put( "Adium",    0);
		collapsedClientCounts.put( "Exodus",   0);
		collapsedClientCounts.put( "Gaim",     0);
		collapsedClientCounts.put( "iChat",    0);
		collapsedClientCounts.put( "JiveTalk", 0);
		collapsedClientCounts.put( "Kopete",   0);
		collapsedClientCounts.put( "Miranda",  0);
		collapsedClientCounts.put( "Pandion",  0);
		collapsedClientCounts.put( "Pidgin",   0);
		collapsedClientCounts.put( "Spark",    0);
		collapsedClientCounts.put( "Trillian", 0);
		collapsedClientCounts.put( "Unknown",  0);

		ArrayList<String> ur = getActiveUserResources(command_jid);
		for (Iterator<String> it = ur.iterator(); it.hasNext(); )
		{
			String jid = it.next();

			Version clientVersion = getClientVersion(jid, timeout);
			if (clientVersion == null)
			{
				continue;
			}

			String[] clientNameAndVersion = new String[2];
			clientNameAndVersion[0]
			                     = clientVersion.getName() != null ? clientVersion.getName() : "";
			clientNameAndVersion[1] = clientVersion.getVersion() != null ? clientVersion.getVersion() : "";
			clientsByJid.put(jid, clientNameAndVersion);

			// Collect counts on full client name and version
			String clientNameVersion = clientVersion.getName();
			if (clientVersion.getVersion() != null)
				clientNameVersion.concat(" " + clientVersion.getVersion());
			if ( !actualClientCounts.containsKey(clientNameVersion) )
			{
				actualClientCounts.put(clientNameVersion, 1);
			}
			else
			{
				actualClientCounts.put(clientNameVersion, actualClientCounts.get(clientNameVersion) + 1);	
			}

			// Collect counts aggregated by client name
			String clientName = clientVersion.getName();
			if (clientName.matches("libpurple"))
			{
				collapsedClientCounts.put("Adium", collapsedClientCounts.get("Adium") + 1);
			}
			else if ( clientName.matches("Exodus") )
			{
				collapsedClientCounts.put("Exodus", collapsedClientCounts.get("Exodus") + 1);
			}
			else if ( clientName.matches("[Gg]aim") )
			{
				collapsedClientCounts.put("Gaim", collapsedClientCounts.get("Gaim") + 1);
			}
			else if ( clientName.matches("iChatAgent") )
			{
				collapsedClientCounts.put("iChat", collapsedClientCounts.get("iChat") + 1);
			}
			else if ( clientName.contains("Miranda") )
			{
				collapsedClientCounts.put("Miranda", collapsedClientCounts.get("Miranda") + 1);
			}
			else if ( clientName.matches("Pandion") )
			{
				collapsedClientCounts.put("Pandion", collapsedClientCounts.get("Pandion") + 1);
			}
			else if (clientName.matches("[Pp]idgin"))
			{
				collapsedClientCounts.put("Pidgin", collapsedClientCounts.get("Pidgin") + 1);
			}
			else if (clientName.startsWith("Spark"))
			{
				collapsedClientCounts.put("Spark", collapsedClientCounts.get("Spark") + 1);
			}
			else if ( clientName.matches("Trillian") )
			{
				collapsedClientCounts.put("Trillian", collapsedClientCounts.get("Trillian") + 1);
			}
			else if ( clientName.isEmpty() )
			{
				collapsedClientCounts.put("Unknown", collapsedClientCounts.get("Unknown") + 1);
			}
			else
			{
				if ( !collapsedClientCounts.containsKey(clientNameVersion) )
				{
					collapsedClientCounts.put(clientNameVersion, 1);
				}
				else
				{
					collapsedClientCounts.put(clientNameVersion, collapsedClientCounts.get(clientNameVersion) + 1);	
				}
			}
		}

		String clientsFormat =  " %-10s | %-15s | %-15s | %-25s\n";
		System.out.printf("\n"+ clientsFormat +"==============================================================================\n",
			"Username", "Resource", "Client", "Version");
		for (Iterator<Entry<String, String[]>> ita = clientsByJid.entrySet().iterator(); ita.hasNext(); )
		{
			Entry<String, String[]> clientByJid = ita.next();
			String fullJid = clientByJid.getKey();
			int indexOfAt = clientByJid.getKey().indexOf('@');
			int indexOfSlash = clientByJid.getKey().indexOf('/');
			System.out.printf(clientsFormat,
				fullJid.substring(0, indexOfAt).length() <= 10
					? fullJid.substring(0, indexOfAt)
					: fullJid.substring(0, 9),
				fullJid.substring(indexOfSlash+1).length() <= 15
					? fullJid.substring(indexOfSlash+1)
					: fullJid.substring(indexOfSlash+1, indexOfSlash+15),
				clientByJid.getValue()[0].length() <= 15
					? clientByJid.getValue()[0]
					: clientByJid.getValue()[0].substring(0, 14),
				clientByJid.getValue()[1].length() <= 25
					? clientByJid.getValue()[1]
					: clientByJid.getValue()[1].substring(0, 24));
		}

		System.out.println("\n * Column contents have been truncated to fit 80 column width.");

		System.out.printf("\n%15s | %s\n===========================\n", "Client Name", "Total");
		for (Iterator<Entry<String, Integer>> itb = collapsedClientCounts.entrySet().iterator(); itb.hasNext(); )
		{
			Entry<String, Integer> countEntry = itb.next();
			System.out.printf("%15s | %s\n", countEntry.getKey(), countEntry.getValue());
		}
	}

	public String getNumOnlineUsers ( String command_jid )
	{
		return (String) callSingleResponseCommand(
				command_jid, "http://jabber.org/protocol/admin#get-online-users-num",
					"onlineusersnum");
	}

	public String getNumActiveUsers ( String command_jid )
	{
		return (String) callSingleResponseCommand(
				command_jid, "http://jabber.org/protocol/admin#get-active-users-num",
					"activeusersnum");
	}

	public String getNumConnectedSessions ( String command_jid )
	{
		return (String) callSingleResponseCommand(
				command_jid, "http://jabber.org/protocol/admin#get-sessions-num",
					"onlineuserssessionsnum");
	}

	private void printServerStats(String command_jid)
	{
		try {
			RemoteCommand cmd = commandManager.getRemoteCommand(command_jid,
					"http://jabber.org/protocol/admin#get-server-stats");
			cmd.execute();
			Form response1 = cmd.getForm();
			for( Iterator<FormField> it = response1.getFields(); it.hasNext(); )
			{
				FormField field = it.next();

				if ( field.getVariable().equals("FORM_TYPE") )
					continue;

				StringBuilder values = new StringBuilder();
				for ( Iterator<String> itv = field.getValues(); itv.hasNext(); )
				{
					values.append(itv.next() + "");
				}
				System.out.println(field.getLabel() + " " + values);
			}
		}
		catch (Exception ex)
		{
			ex.printStackTrace();
		}
	}

	public static void main(String[] args)
	{
		XmppAdminTool poller = new XmppAdminTool();
		CommandLineParser parser = new PosixParser();
		CommandLine cmdLine;
		try
		{
			cmdLine = parser.parse(poller.opts, args);
			if ( (cmdLine.getOptions().length == 0) || cmdLine.hasOption("h") )
			{
				HelpFormatter formatter = new HelpFormatter();
				formatter.printHelp( "xat", poller.opts );
			}
			else
			{
				if ( cmdLine.hasOption("h") )
				{
					Integer port;
					if ( cmdLine.hasOption("o") )
					{
						port = Integer.parseInt(cmdLine.getOptionValue("o"));
					}
					else
					{
						port = XmppAdminTool.DEFAULT_PORT;
					}

					poller.conf = new ConnectionConfiguration(cmdLine.getOptionValue("h"), port);
					poller.conf.setVerifyChainEnabled(false); // re-enable these guys at some point
					poller.conf.setVerifyRootCAEnabled(false);
				}
				else if ( cmdLine.hasOption("c") )
				{
					poller.conf = new ConnectionConfiguration(cmdLine.getOptionValue("c"));
					poller.conf.setVerifyChainEnabled(false); // re-enable these guys at some point
					poller.conf.setVerifyRootCAEnabled(false);
				}
				else
				{
					System.out.println("Error: You must supply either hostname or command-jid.");
					System.exit(1);
				}

				if ( !cmdLine.hasOption("c") )
				{
					System.out.println("Error: command-jid is required.");
					System.exit(1);
				}

				if ( cmdLine.hasOption("P") )
					poller.conf.setTruststorePath( cmdLine.getOptionValue("P") );
				if ( cmdLine.hasOption("Y") )
					poller.conf.setTruststoreType( cmdLine.getOptionValue("Y"));
//				poller.conf.setTruststorePassword(DEFAULT_TRUSTSTORE_PASSWORD);

				if ( !cmdLine.hasOption("u") || null == cmdLine.getOptionValue("u") )
				{
					System.out.println("Error: You must supply a username.");
					System.exit(1);
				}

				StringBuilder password = new StringBuilder();
				if ( cmdLine.hasOption("p") )
				{
					if ( cmdLine.getOptionValue("p").equals("-") )
					{
						char[] passwordChars = System.console().readPassword("Password: ");
						password.append(passwordChars);
					}
					else
					{
						password.append(cmdLine.getOptionValue("p"));
					}
				}

				String resource;
				if ( cmdLine.hasOption("r") )
				{
					resource = cmdLine.getOptionValue("r");
				}
				else
				{
					resource = XmppAdminTool.DEFAULT_RESOURCE;
				}

				poller.connect(cmdLine.getOptionValue("u"), password.toString(), resource);
				
				if ( cmdLine.hasOption("v") )
					poller.displayVerboseMessages = true;
				if ( cmdLine.hasOption("d") )
					poller.displayDebugMessages = true;

				if ( cmdLine.hasOption("C") )
					poller.printSupportedCommands(cmdLine.getOptionValue("c"));
				
				if ( cmdLine.hasOption("J") )
				{
					ArrayList<String> activeUsers = poller.getActiveUsers(cmdLine.getOptionValue("c"));
					if ( !activeUsers.isEmpty() )
					{
						for (Iterator<String> it = activeUsers.listIterator(); it.hasNext();)
						{
							System.out.println( (String) it.next() );
						}
					}
					else
					{
						System.out.println("No active users");
					}
				}

				if ( cmdLine.hasOption("Z") )
					poller.printServerStats(cmdLine.getOptionValue("c"));

				if ( cmdLine.hasOption("O") )
					System.out.println("Online Users: " + poller.getNumOnlineUsers(cmdLine.getOptionValue("c")));

				if ( cmdLine.hasOption("A") )
					System.out.println("Active Users: " + poller.getNumActiveUsers(cmdLine.getOptionValue("c")));
				
				if ( cmdLine.hasOption("S") )
					System.out.println("Connected Sessions: " + poller.getNumConnectedSessions(cmdLine.getOptionValue("c")));
				
				if ( cmdLine.hasOption("K") )
				{
					Object timeout = cmdLine.getOptionValue("T", "10");
					try
					{
						timeout = Integer.parseInt((String)timeout);
					}
					catch(NumberFormatException nfe)
					{
						System.out.println("Error: Invalid number supplied for timeout");
						System.exit(1);
					}
					
					poller.printClientVersions(cmdLine.getOptionValue("c"), (Integer) timeout);
				}
				
				poller.disconnect();
			}
			
			System.exit(0);
		}
		catch ( ParseException px )
		{
			System.out.println( "Error: Invalid command line opts.");
			System.exit(1);
		}
	}

}
