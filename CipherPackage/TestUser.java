package CipherPackage;

import static org.junit.Assert.*;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class TestUser {
	User User1;
	User User2;
	
	@Before
    public void setUp() throws Exception {
		User1 = new User(null);
		User2 = new User(User1);
    }
	
	@Test
	public void testMsg() {	
		String originalMsg = "Hello User2!";
		String encryptMsg = User1.encrypt(originalMsg);
		String decryptMsg = User2.decrypt(encryptMsg);
		
		Assert.assertEquals(originalMsg, decryptMsg);
	}
	
	@Test
	public void testSessionKeys() {	
		String[] strings1 = User1.getSessionPair();
		String[] strings2 = User2.getSessionPair();
		
		Assert.assertNotNull(strings1);
		Assert.assertNotNull(strings2);
		Assert.assertEquals(strings1[0], strings2[0]);
		Assert.assertEquals(strings1[1], strings2[1]);
	}
	
	@Test
	public void testDHKeys() {	
		String[] strings1 = User1.getDHPair();
		String[] strings2 = User2.getDHPair();
		
		Assert.assertNotNull(strings1);
		Assert.assertNotNull(strings2);
		Assert.assertNotEquals(strings1[0], strings2[0]);
		Assert.assertNotEquals(strings1[1], strings2[1]);
	}
}
