package net.ossindex.maven.plugin;

import java.io.File;

import org.apache.maven.artifact.repository.ArtifactRepository;
import org.apache.maven.artifact.repository.ArtifactRepositoryPolicy;
import org.apache.maven.artifact.repository.MavenArtifactRepository;
import org.apache.maven.artifact.repository.layout.DefaultRepositoryLayout;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.MojoExecution;
import org.apache.maven.plugin.testing.AbstractMojoTestCase;
import org.apache.maven.plugin.testing.MojoRule;
import org.apache.maven.plugin.testing.resources.TestResources;
import org.apache.maven.project.MavenProject;
import org.apache.maven.settings.Settings;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.Assert;


public class OssIndexMojoTest {
    @Rule
    public MojoRule mojoRule = new MojoRule();

    @Rule
    public TestResources testResources = new TestResources();

    private MavenProject project;
    private MavenSession session;

    private OssIndexMojo mojo;

    @Before
    public void setUp() throws Exception {
        File projectDir = testResources.getBasedir("project-invalid");
        File pom = new File( projectDir, "pom.xml" );
        Assert.assertNotNull( pom );
        Assert.assertTrue( pom.exists());
        project = mojoRule.readMavenProject(projectDir);

//        // Generate session
//        session = mojoRule.newMavenSession(project);

        // add localRepo - framework doesn't do this on its own
//        ArtifactRepository localRepo = createLocalArtifactRepository();
//        session.getRequest().setLocalRepository(localRepo);

        // Generate Execution and Mojo for testing
//        MojoExecution execution = mojoRule.newMojoExecution("audit");
//        mojo = (OssIndexMojo) mojoRule.lookupConfiguredMojo(session, execution);

        mojo = (OssIndexMojo)mojoRule.lookupMojo("audit", pom);

        final MavenProject mvnProject = new MavenProject() ;
        mvnProject.setFile( projectDir ) ;
        this.mojoRule.setVariableValueToObject( mojo, "project", mvnProject );
    }

//    /**
//     * Generate a local repository
//     * @return local repository object
//     */
//    private ArtifactRepository createLocalArtifactRepository() {
//        return new MavenArtifactRepository("local",
//                localRepoDir.toURI().toString(),
//                new DefaultRepositoryLayout(),
//                new ArtifactRepositoryPolicy( true, ArtifactRepositoryPolicy.UPDATE_POLICY_ALWAYS, ArtifactRepositoryPolicy.CHECKSUM_POLICY_IGNORE ),
//                new ArtifactRepositoryPolicy( true, ArtifactRepositoryPolicy.UPDATE_POLICY_ALWAYS, ArtifactRepositoryPolicy.CHECKSUM_POLICY_IGNORE )
//
//        );
//    }


    @Test
    public void testInvalidProject() throws Exception {

//        File projectDir = this.resources.getBasedir( "project-invalid" );
//        File pom = new File( projectDir, "pom.xml" );
//
//        Assert.assertNotNull( pom );
//        Assert.assertTrue( pom.exists());
//
//        this.mojoRule.executeMojo(projectDir, "ossindex-maven-plugin");

//        OssIndexMojo mojo = new OssIndexMojo();
//        mojo = (OssIndexMojo) configureMojo(mojo, extractPluginConfiguration("ossindex-maven-plugin", pom));
//        Assert.assertNotNull( mojo );
//        mojo.execute();

        Assert.assertNotNull( mojo );
        mojo.execute();
    }
}
