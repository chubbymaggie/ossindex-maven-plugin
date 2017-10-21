/**
 * Copyright (c) 2015-2017 Vör Security Inc.
 * All rights reserved.
 * <p>
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * * Neither the name of the <organization> nor the
 * names of its contributors may be used to endorse or promote products
 * derived from this software without specific prior written permission.
 * <p>
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
package net.ossindex.maven.utils;

import org.junit.After;
import org.junit.Before;

/** Test the dependency auditor
 *
 * @author Ken Duck
 *
 */
public class DependencyAuditorTests {
    private DependencyAuditor auditor;

    @Before
    public void before() {
        auditor = new DependencyAuditor();
    }

    @After
    public void after() {
        auditor.close();
    }

//	@Test
//	public void testCommonsLang3() throws IOException
//	{
//		PackageDependency dep = new PackageDependency("maven", "commons-lang3", "3.4");
//		auditor.setDependencyInformation(new PackageDependency[] {dep});
//		ScmResource scm = dep.getScm();
//		assertNotNull(scm);
//	}
//	@Test
//	public void testGoogleCollectRange() throws IOException
//	{
//		PackageDependency dep = new PackageDependency("maven", "google-collect", ">0");
//		auditor.setDependencyInformation(new PackageDependency[] {dep});
//		ScmResource scm = dep.getScm();
//		assertNotNull(scm);
//	}
//	@Test
//	@Ignore
//	public void testGoogleCollect() throws IOException
//	{
//		PackageDependency dep = new PackageDependency("maven", "google-collect", "snapshot-20080530");
//		auditor.setDependencyInformation(new PackageDependency[] {dep});
//		ScmResource scm = dep.getScm();
//		assertNotNull(scm);
//	}
//	@Test
//	public void testJavaxMail() throws IOException
//	{
//		PackageDependency dep = new PackageDependency("maven", "javax.mail", "mail", "1.5.0-b01");
//		auditor.setDependencyInformation(new PackageDependency[] {dep});
//		ScmResource scm = dep.getScm();
//		assertNotNull(scm);
//		assertNotNull(scm.getVulnerabilities());
//		boolean vulnerable = false;
//		for(VulnerabilityResource vulnerability: scm.getVulnerabilities())
//		{
//			String[] versions = vulnerability.getVersions();
//			assertNotNull(versions);
//			if(vulnerability.appliesTo(dep.getVersion()))
//			{
//				vulnerable = true;
//			}
//		}
//		assertTrue(vulnerable);
//	}
//	@Test
//	public void testHttpclient() throws IOException
//	{
//		PackageDependency dep = new PackageDependency("maven", "org.apache.httpcomponents", "httpclient", "4.3.6");
//		auditor.setDependencyInformation(new PackageDependency[] {dep});
//		ScmResource scm = dep.getScm();
//		assertNotNull(scm);
//		assertNotNull(scm.getVulnerabilities());
//		for(VulnerabilityResource vulnerability: scm.getVulnerabilities())
//		{
//			String[] versions = vulnerability.getVersions();
//			assertNotNull(versions);
//			if(vulnerability.appliesTo(dep.getVersion()))
//			{
//				System.err.println("WAT: " + dep.getVersion());
//				System.err.println("WAT: " + vulnerability.getId());
//			}
//			assertFalse(vulnerability.appliesTo(dep.getVersion()));
//		}
//	}

}
