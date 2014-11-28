package org.zaproxy.zap.extension.retire;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class RetireUtilTest {

	@Test
	public void versions_should_be_above() {
		assertTrue(RetireUtil.isAtOrAbove("0.0.1", "0.0.0"));
		assertTrue(RetireUtil.isAtOrAbove("0.1.0", "0.0.9"));
		assertTrue(RetireUtil.isAtOrAbove("0.10.1", "0.9.0"));
		assertTrue(RetireUtil.isAtOrAbove("0.0.10", "0.0.9"));
		assertTrue(RetireUtil.isAtOrAbove("0.0.10", "0.0.09"));
		assertTrue(RetireUtil.isAtOrAbove("0.1", "0.0.1"));
		assertTrue(RetireUtil.isAtOrAbove("0.2.0", "0.1"));
		assertTrue(RetireUtil.isAtOrAbove("0.0.1-beta", "0.0.1-alpha"));
		assertTrue(RetireUtil.isAtOrAbove("0.0.1", "0.0.1-alpha"));
	}
	@Test
	public void versions_should_be_at() {
		assertTrue(RetireUtil.isAtOrAbove("0.0.1", "0.0.1"));
		assertTrue(RetireUtil.isAtOrAbove("0.1.1", "0.1.1"));
		assertTrue(RetireUtil.isAtOrAbove("0.1.0", "0.1"));
	}
	@Test
	public void versions_should_not_be_above() {
		assertFalse(RetireUtil.isAtOrAbove("0.0.1", "0.0.2"));
		assertFalse(RetireUtil.isAtOrAbove("0.0.9", "0.0.10"));
		assertFalse(RetireUtil.isAtOrAbove("0.1.1", "0.1.2"));
		assertFalse(RetireUtil.isAtOrAbove("0.0.9", "0.1"));
		assertFalse(RetireUtil.isAtOrAbove("0.1", "0.2.0"));
	}
}
