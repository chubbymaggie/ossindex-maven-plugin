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
package net.ossindex.maven.plugin;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import net.ossindex.common.VulnerabilityDescriptor;
import net.ossindex.maven.utils.DependencyAuditor;
import net.ossindex.maven.utils.MavenIdWrapper;
import net.ossindex.maven.utils.MavenPackageDescriptor;
import net.ossindex.maven.utils.OssIndexResultsWrapper;
import org.apache.commons.io.FileUtils;
import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.resolver.filter.ArtifactFilter;
import org.apache.maven.artifact.resolver.filter.OrArtifactFilter;
import org.apache.maven.artifact.resolver.filter.ScopeArtifactFilter;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.Component;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.project.DefaultProjectBuildingRequest;
import org.apache.maven.project.MavenProject;
import org.apache.maven.project.ProjectBuildingRequest;
import org.apache.maven.settings.Proxy;
import org.apache.maven.settings.Settings;
import org.apache.maven.shared.dependency.graph.DependencyGraphBuilder;
import org.apache.maven.shared.dependency.graph.DependencyNode;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import java.io.*;
import java.util.*;

/** Cross reference the project against information in OSS Index to identify
 * security and maintenance problems.
 *
 * @author Ken Duck
 *
 */
@Mojo(name = "audit")
public class OssIndexMojo extends AbstractMojo {

    /**
     * Aggregate all of the results into a static list (so all module builds can access the same list).
     */
    private static List<MavenPackageDescriptor> results = new LinkedList<>();

    static {
        // Default log4j configuration. Hides configuration warnings.
        BasicConfigurator.configure();
        Logger.getRootLogger().setLevel(Level.WARN);
    }

    /**
     * @parameter default-value="${project}"
     */
    @Parameter(defaultValue = "${project}", readonly = true, required = true)
    private MavenProject project;
    /**
     * Comma separated list of artifacts to ignore errors for
     */
    @Parameter(property = "audit.ignore", defaultValue = "")
    private String ignore;
    private Set<String> ignoreSet = new HashSet<>();

    /**
     * Comma separated list of ignored vulnerability IDs.
     */
    @Parameter(property = "audit.ignoreIds", defaultValue = "")
    private String ignoreIds;
    private Set<Long> ignoreIdSet = new HashSet<>();

    /**
     * Should the plugin cause a build failure?
     */
    @Parameter(property = "audit.failOnError", defaultValue = "true")
    private String failOnError;

    /**
     * Comma separated list of output file paths
     */
    @Parameter(property = "audit.output", defaultValue = "")
    private String output;

    /**
     * Should the plugin cause a build failure?
     */
    @Parameter(property = "audit.quiet", defaultValue = "false")
    private String quiet;

    /**
     * Should the plugin cause a build failure?
     */
    @Parameter(property = "audit.scope")
    private String scope;

    /**
     * Report ignored issues as warnings
     */
    @Parameter(property = "audit.warnOnIgnore", defaultValue = "false")
    private String warnOnIgnore;

    private Set<File> outputFiles = new HashSet<>();
    @Parameter(defaultValue = "${session}", readonly = true, required = true)
    private MavenSession session;
    /**
     * Information from the settings.xml file
     */
    @Parameter(defaultValue = "${settings}", readonly = true)
    private Settings settings;
    /**
     * The dependency tree builder to use.
     */
    @Component(hint = "default")
    private DependencyGraphBuilder dependencyGraphBuilder;

    /**
     * Start time used for calculating elapsed time of plugin
     */
    private long start;

    /**
     * Count the total number of failures
     */
    private int failedPackages;

    /**
     * Count the total number of failures
     */
    private int failures;

    /**
     * Count the number of ignored vulnerabilities
     */
    private int ignored;

    /**
     * Count the number of analyzed dependencies
     */
    private int dependencies;

    // Your other mojo parameters and code here
    /*
	 * (non-Javadoc)
	 * @see org.apache.maven.plugin.Mojo#execute()
	 */
    @Override
    public void execute() throws MojoFailureException {
        start = System.currentTimeMillis();
        List<Proxy> proxies = new LinkedList<>();
        if (settings != null) {
            proxies = settings.getProxies();
            if (proxies != null && proxies.size() > 0) {
                getLog().debug("Using proxy");
            }
        }

        MavenIdWrapper moduleId = new MavenIdWrapper();
        moduleId.setGroupId(project.getGroupId());
        moduleId.setArtifactId(project.getArtifactId());
        moduleId.setVersion(project.getVersion());

        ignoreSet.addAll(parseList(ignore));

        for (String token : parseList(ignoreIds)) {
            ignoreIdSet.add(Long.valueOf(token));
        }

        for (String token : parseList(output)) {
            outputFiles.add(new File(token));
        }

        DependencyAuditor auditor = new DependencyAuditor(proxies);

        try {
            if (!isTrue(quiet)) {
                getLog().info("OSS Index dependency audit");
            }

            // Build the ArtifactFilter to consider the scope passed in on as a system property
            ArtifactFilter artifactFilter = null;
            if (scope != null) {
                String[] tokens = scope.split(",");
                switch (tokens.length) {
                    case 1:
                        artifactFilter = new ScopeArtifactFilter(scope.trim());
                        break;
                    default:
                        artifactFilter = new OrArtifactFilter();
                        for (String token: tokens) {
                            token = token.trim();
                            ((OrArtifactFilter)artifactFilter).add(new ScopeArtifactFilter(token));
                        }
                        break;
                }
            }
            ProjectBuildingRequest buildingRequest =
                    new DefaultProjectBuildingRequest(session.getProjectBuildingRequest());

            buildingRequest.setProject(project);

            // The computed dependency tree root node of the Maven project.
            DependencyNode rootNode = dependencyGraphBuilder.buildDependencyGraph(buildingRequest, artifactFilter);
            List<DependencyNode> depNodes = rootNode.getChildren();

            for (DependencyNode dep : depNodes) {
                Artifact artifact = dep.getArtifact();
                auditor.add(artifact.getGroupId(), artifact.getArtifactId(), artifact.getVersion(), dep);
            }

            // Perform the audit
            Collection<MavenPackageDescriptor> results = auditor.run();

            // Analyze the results
            for (MavenPackageDescriptor pkg : results) {
                dependencies++;
                pkg.setModule(moduleId);
                String idPkg = pkg.getMavenPackageId();
                String idVer = pkg.getMavenVersionId();
                if (!ignoreSet.contains(idPkg) && !ignoreSet.contains(idVer)) {
                    MavenIdWrapper parentPkg = pkg.getParent();

                    int pkgFailures = report(parentPkg, pkg);
                    if (pkgFailures > 0) {
                        failedPackages++;
                        this.failures += pkgFailures;
                    }
                } else {
                    ignored++;

                    if (isTrue(warnOnIgnore)) {
                        MavenIdWrapper parentPkg = pkg.getParent();
                        report(parentPkg, pkg, false);
                    }
                }
            }

            // Aggregate results for all modules
            OssIndexMojo.results.addAll(results);

            // Report to various file loggers
            for (File file : outputFiles) {
                if (file.getName().endsWith(".txt")) {
                    exportTxt(file, OssIndexMojo.results);
                }
                if (file.getName().endsWith(".json")) {
                    exportJson(file, OssIndexMojo.results);
                }
                if (file.getName().endsWith(".xml")) {
                    exportXml(file, OssIndexMojo.results);
                }
            }
        } catch (Throwable e) {
            getLog().warn(e.getClass().getSimpleName() + " running OSS Index audit: " + e.getMessage());
            getLog().debug(e);
        } finally {
            auditor.close();
        }

        if (isTrue(quiet)) {
            logSummary();
        }

        if (failures > 0) {
            if (isTrue(failOnError)) {
                throw new MojoFailureException(failures + " known vulnerabilities affecting project dependencies");
            }
        }
    }

    private static List<String> parseList(String list) {
        List<String> result = new ArrayList<>();
        if (list != null) {
            list = list.trim();
            if (!list.isEmpty()) {
                String[] tokens = list.split(",");
                for (String token : tokens) {
                    result.add(token.trim());
                }
            }
        }
        return result;
    }

    private boolean isTrue(String flag) {
        return "true".equalsIgnoreCase(flag);
    }

    private void logSummary() {
        StringBuilder sb = new StringBuilder();
        long end = System.currentTimeMillis();
        long diff = end - start;
        sb.append("Audited packages: ").append(dependencies);
        sb.append(", Ignored: ").append(ignored);
        sb.append(", Vulnerable: ").append(failedPackages);
        sb.append(" [").append(failures).append(" issues]");
        sb.append(", Time elapsed: ").append(diff).append(" ms");
        getLog().info(sb.toString());
    }

    /**
     * Export the results to a text file
     * @param file File to export to
     * @param results Data to export
     */
    private void exportTxt(File file, Collection<MavenPackageDescriptor> results) {
        MavenIdWrapper lastModule = null;
        try (PrintWriter out = new PrintWriter(new FileWriter(file))) {
            for (MavenPackageDescriptor pkg : results) {
                MavenIdWrapper parentPkg = pkg.getParent();
                MavenIdWrapper module = pkg.getModule();
                String pkgId = pkg.getMavenVersionId();
                int total = pkg.getVulnerabilityTotal();

                if (!module.equals(lastModule)) {
                    out.println();
                    out.println("==============================================================");
                    out.println(module);
                    out.println("==============================================================");
                    lastModule = module;
                }

                List<VulnerabilityDescriptor> vulnerabilities = pkg.getVulnerabilities();
                if (vulnerabilities != null && !vulnerabilities.isEmpty()) {
                    int matches = pkg.getVulnerabilityMatches();
                    out.println();
                    out.println("--------------------------------------------------------------");
                    out.println(pkgId + "  [VULNERABLE]");
                    if (parentPkg != null) {
                        String parentId = parentPkg.getMavenVersionId();
                        out.println("  required by " + parentId);
                    }
                    out.println(total + " known vulnerabilities, " + matches + " affecting installed version");
                    out.println("");
                    for (VulnerabilityDescriptor vulnerability : vulnerabilities) {
                        out.println(vulnerability.getTitle());
                        out.println(vulnerability.getUriString());
                        out.println(vulnerability.getDescription());
                        out.println("");
                    }
                    out.println("--------------------------------------------------------------");
                    out.println();
                } else {
                    if (total > 0) {
                        out.println(pkgId + ": " + total + " known vulnerabilities, 0 affecting installed version");
                    } else {
                        out.println(pkgId + ": No known vulnerabilities");
                    }
                }
            }
        } catch (IOException e) {
            getLog().warn("Cannot export to " + file + ": " + e.getMessage());
        }
    }

    /**
     * Export the results to a JSON file
     * @param file File to export to
     * @param results Data to export
     */
    private void exportJson(File file, Collection<MavenPackageDescriptor> results) {
        Gson gson = new GsonBuilder().disableHtmlEscaping().setPrettyPrinting().create();
        String json = gson.toJson(results);
        try {
            FileUtils.writeStringToFile(file, json);
        } catch (IOException e) {
            getLog().warn("Cannot export to " + file + ": " + e.getMessage());
        }
    }

    /**
     * Export the results to an XML file
     * @param file File to export to
     * @param results Data to export
     */
    private void exportXml(File file, Collection<MavenPackageDescriptor> results) {
        OssIndexResultsWrapper wrapper = new OssIndexResultsWrapper(results);
        OutputStream out = null;
        try {
            out = new FileOutputStream(file);
            JAXBContext context = JAXBContext.newInstance(OssIndexResultsWrapper.class);
            Marshaller m = context.createMarshaller();
            m.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);
            m.marshal(wrapper, out);

        } catch (FileNotFoundException e) {
            getLog().warn("Cannot export to " + file + ": " + e.getMessage());
        } catch (JAXBException e) {
            getLog().debug(e);
            getLog().warn("Cannot export to " + file + ": " + e.getMessage());
        } finally {
            if (out != null) {
                try {
                    out.close();
                } catch (IOException e) {
                    getLog().warn("Exception closing " + file + ": " + e.getMessage());
                }
            }
        }
    }

    /** Reports on all identified packages and known vulnerabilities.
     */
    private int report(MavenIdWrapper parentPkg, MavenPackageDescriptor pkg) throws IOException {
        return report(parentPkg, pkg, true);
    }

    private int report(MavenIdWrapper parentPkg, MavenPackageDescriptor pkg, boolean logToError) throws IOException {
        String pkgId = pkg.getMavenVersionId();
        int total = pkg.getVulnerabilityTotal();

        List<VulnerabilityDescriptor> vulnerabilities = filterIgnoredVulnerabilities(pkg.getVulnerabilities(), pkg, pkg.getParent());

        int failures = 0;
        if (vulnerabilities != null && !vulnerabilities.isEmpty()) {
            int matches = vulnerabilities.size();
            reportVulnerabilities(parentPkg, logToError, pkgId, vulnerabilities, total, matches);
            failures += matches;
        } else {
            if (!isTrue(quiet)) {
                if (total > 0) {
                    getLog().info(pkgId + " - " + total + " known vulnerabilities, 0 affecting installed version");
                } else {
                    getLog().info(pkgId + " - No known vulnerabilities");
                }
            }
        }

        return failures;
    }

    private void reportVulnerabilities(MavenIdWrapper parentPkg, boolean logToError, String pkgId, List<VulnerabilityDescriptor> vulnerabilities, int total, int matches) {
        MismatchLogger logger = logToError ? new ErrorLogger() : new WarnLogger();
        logger.log("");
        logger.log("--------------------------------------------------------------");
        logger.log(pkgId + "  [VULNERABLE]");
        if (parentPkg != null) {
            String parentId = parentPkg.getMavenVersionId();
            logger.log("  required by " + parentId);
        }
        logger.log(total + " known vulnerabilities, " + matches + " affecting installed version");
        logger.log("");

        for (VulnerabilityDescriptor vulnerability : vulnerabilities) {
            logger.log(vulnerability.getTitle());
            logger.log(vulnerability.getUriString());
            logger.log(vulnerability.getDescription());
            logger.log("");
        }
        logger.log("--------------------------------------------------------------");
        logger.log("");
    }

    private List<VulnerabilityDescriptor> filterIgnoredVulnerabilities(List<VulnerabilityDescriptor> vulnerabilities, MavenPackageDescriptor pkg, MavenIdWrapper parentPkg) {
        if (ignoreIdSet.isEmpty() || vulnerabilities == null || vulnerabilities.isEmpty()) {
            return vulnerabilities;
        }
        List<VulnerabilityDescriptor> result = new ArrayList<>();
        for (VulnerabilityDescriptor desc : vulnerabilities) {
            if (!ignoreIdSet.contains(desc.getId())) {
                result.add(desc);
            } else {
                if (isTrue(warnOnIgnore)) {
                    reportVulnerabilities(parentPkg, false, pkg.getMavenPackageId(), Collections.singletonList(desc), 1, 1);
                }
            }
        }
        return result;
    }

    private interface MismatchLogger {
        void log(String message);
    }

    private class ErrorLogger implements MismatchLogger {
        @Override
        public void log(String message) {
            getLog().error(message);
        }
    }

    private class WarnLogger implements MismatchLogger {
        @Override
        public void log(String message) {
            getLog().warn(message);
        }
    }

}
