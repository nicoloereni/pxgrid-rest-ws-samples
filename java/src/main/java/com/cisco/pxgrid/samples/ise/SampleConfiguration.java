package com.cisco.pxgrid.samples.ise;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.*;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

public class SampleConfiguration {
	private String[] hostnames;
	private String nodeName;
	private String password;
	private String description;
	private String keystoreFilename;
	private String keystorePassword;
	private String truststoreFilename;
	private String truststorePassword;

	private SSLContext sslContext;
	private Options options = new Options();

	public SampleConfiguration() {
		options.addOption("a", "hostname", true, "Host name (multiple accepted)");
		options.addOption("u", "nodename", true, "Node name");
		options.addOption("w", "password", true, "Password (not required if keystore is specified)");
		options.addOption("d", "description", true, "Description (optional)");
		options.addOption("k", "keystorefilename", true, "Keystore .jks filename (not required if password is specified)");
		options.addOption("p", "keystorepassword", true, "Keystore password (not required if password is specified)");
		options.addOption("t", "truststorefilename", true, "Truststore .jks filename");
		options.addOption("q", "truststorepassword", true, "Truststore password");
	}

	public String getNodeName() {
		return nodeName;
	}

	public String[] getHostnames() {
		return hostnames;
	}

	public String getPassword() {
		return password;
	}

	public String getDescription() {
		return description;
	}

	public SSLContext getSSLContext() {
		return sslContext;
	}

	public Options getOptions() {
		return options;
	}

	private KeyManager[] getKeyManagers() throws IOException, GeneralSecurityException {

		System.out.println("keystoreFilename " + keystoreFilename);
		if (keystoreFilename == null) {
			return null;
		}
		KeyStore ks = KeyStore.getInstance("JKS");
		FileInputStream in = new FileInputStream(keystoreFilename);
		ks.load(in, keystorePassword.toCharArray());
		in.close();
		KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
		kmf.init(ks, keystorePassword.toCharArray());
		System.out.println("before kmf.getKeyManagers");
		return kmf.getKeyManagers();
	}

	private TrustManager[] getTrustManagers() throws IOException, GeneralSecurityException {
		KeyStore ks = KeyStore.getInstance("JKS");
		System.out.println("ks " + ks);
		FileInputStream in = new FileInputStream(truststoreFilename);
		ks.load(in, truststorePassword.toCharArray());
		in.close();
		TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		tmf.init(ks);
		return tmf.getTrustManagers();
	}

	public void parse(String[] args) throws ParseException, IOException, GeneralSecurityException {
//		CommandLineParser parser = new DefaultParser();
//		CommandLine cmd = parser.parse(options, args);

//		------ config ------
//		hostname = ise24fc3.lab10.com
//		nodename = IOTSolution/Users/nicolo/Documents/pxgrid-rest-ws/java/src/main/java/com/cisco/pxgrid/samples/ise/certificates
//		password = (not specified)
//		description = (not specified)
//		keystorefilename = /Applications/sdk24/pxgrid-sdk-2.0.0.14/samples/bin/sdk24.jks
//		keystorepassword = Cisco123
//		truststorefilename = /Applications/sdk24/pxgrid-sdk-2.0.0.14/samples/bin/sdk24root.jks
//		truststorepassword = Cisco123
//				--------------------

		hostnames = new String[]{"int-nac-ise.intra.nozominetworks.com"};
		nodeName = "nozomitestcert";
		password = "";
//		description = cmd.getOptionValue("d");
//		keystoreFilename = "/Library/Java/JavaVirtualMachines/jdk1.8.0_111.jdk/Contents/Home/jre/lib/security/cacerts";
//		keystorePassword = "changeit";
		truststoreFilename = "/Users/nicolo/Documents/pxgrid-rest-ws/java/src/main/java/com/cisco/pxgrid/samples/ise/certificates/cert.jks";
		truststorePassword = "Nozomi_0109";

		if (hostnames == null) throw new IllegalArgumentException("Missing host name");
		if (nodeName == null) throw new IllegalArgumentException("Missing node name");
		if (truststoreFilename == null) throw new IllegalArgumentException("Missing truststore filename");
		if (truststorePassword == null) throw new IllegalArgumentException("Missing truststore password");

		sslContext = SSLContext.getInstance("TLSv1.2");
		TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {
			public X509Certificate[] getAcceptedIssuers() {
				return null;
			}

			@Override
			public void checkClientTrusted(X509Certificate[] arg0, String arg1) {
				// Not implemented
			}

			@Override
			public void checkServerTrusted(X509Certificate[] arg0, String arg1) {
				// Not implemented
			}
		} };
		sslContext.init(getKeyManagers(), getTrustManagers(), null);

//		// Print parse result
//		System.out.println("------ config ------");
//		for (Option option : options.getOptions()) {
//			String[] values = cmd.getOptionValues(option.getOpt());
//			if (values != null) {
//				for (String value : values) {
//					System.out.println("  " + option.getLongOpt() + " = " + value);
//				}
//			}
//			else {
//				System.out.println("  " + option.getLongOpt() + " = (not specified)");
//			}
//		}
//		System.out.println("--------------------");
	}

	public void printHelp(String commandLineSyntax) {
		HelpFormatter formatter = new HelpFormatter();
		formatter.printHelp(commandLineSyntax, options);
	}
}
