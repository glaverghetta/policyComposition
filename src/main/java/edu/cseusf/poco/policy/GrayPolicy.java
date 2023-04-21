package edu.cseusf.poco.policy;

public abstract class GrayPolicy extends Policy {

	// Maximum and minimum values for security policies.
	public static final int SECURITY_VALUE_MAX = 100;
	public static final int SECURITY_VALUE_MIN = 0;
	
	// The security value/rating that indicates how well the policy is being followed.
	// SECURITY_VALUE_MAX = completely followed, SECURITY_VALUE_MIN = completely violated.
	private int securityValue = SECURITY_VALUE_MAX;

	public int getSecurityValue() {
		return securityValue;
	}

	public void setSecurityValue(int securityValue) {
		if(securityValue > SECURITY_VALUE_MAX)
			securityValue = SECURITY_VALUE_MAX;
		if(securityValue < SECURITY_VALUE_MIN)
			securityValue = SECURITY_VALUE_MIN;
		this.securityValue = securityValue;
	}
	
}