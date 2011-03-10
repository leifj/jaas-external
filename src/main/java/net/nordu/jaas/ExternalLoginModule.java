package net.nordu.jaas;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class ExternalLoginModule implements LoginModule {

	private Subject subject;
	private CallbackHandler callbackHandler;
	private Map<String, ?> sharedState;
	private Map<String, ?> options;
	
	protected final Log logger = LogFactory.getLog(this.getClass());

	
	@Override
	public boolean abort() throws LoginException {
		logger.info("abort");
		return true;
	}

	@Override
	public boolean commit() throws LoginException {
		logger.info("commit");
		return true;
	}

	@Override
	public void initialize(Subject subject, CallbackHandler callbackHandler,Map<String, ?> sharedState, Map<String, ?> options) {
		
		logger.info("initialize");
		
		this.subject = subject;
	    this.callbackHandler = callbackHandler;
	    this.sharedState = sharedState;
	    this.options = options;
	}

	@Override
	public boolean login() throws LoginException {
		
		logger.info("login");
		
		try {
			NameCallback nameCallback = new NameCallback("Username");
		    PasswordCallback passwordCallback = new PasswordCallback("Password", false);
		    Callback[] callbacks = new Callback[]{nameCallback, passwordCallback};
		    callbackHandler.handle(callbacks);
	
		    String username = nameCallback.getName();
		    char[] password = passwordCallback.getPassword();
		    passwordCallback.clearPassword();
		    
		    Runtime rt = Runtime.getRuntime();
		    String program = (String)options.get("program");
		    if (logger.isDebugEnabled()) {
		    	logger.debug("About to execute: "+program);
		    }
		    Process pr = rt.exec(program);
		    OutputStreamWriter out = new OutputStreamWriter(pr.getOutputStream());
		    out.write(username+" "+new String(password));
		    out.close();
		    BufferedReader input = new BufferedReader(new InputStreamReader(pr.getInputStream()));
		    
            String line=null;
            while((line=input.readLine()) != null) {
                if (logger.isDebugEnabled())
                	logger.debug(line);
            }

            int exitVal = pr.waitFor();
            if (exitVal > 0)
            	throw new LoginException("Return value: "+exitVal);
		    
		} catch (LoginException ex) {
			ex.printStackTrace();
			throw ex;
		} catch (Exception ex) {
			ex.printStackTrace();
			throw new LoginException(ex.getMessage());
		}
		
		return true;
	}

	@Override
	public boolean logout() throws LoginException {
		logger.info("logout");
		return true;
	}

}
