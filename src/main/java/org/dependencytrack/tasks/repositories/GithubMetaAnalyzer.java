/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.tasks.repositories;

import alpine.common.logging.Logger;
import com.github.packageurl.PackageURL;
import org.dependencytrack.exception.MetaAnalyzerException;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.RepositoryType;
import org.kohsuke.github.GHBranch;
import org.kohsuke.github.GHCommit;
import org.kohsuke.github.GHRelease;
import org.kohsuke.github.GHRepository;
import org.kohsuke.github.GitHub;

import java.io.IOException;

import static org.apache.commons.lang3.StringUtils.isBlank;
import static org.apache.commons.lang3.StringUtils.isNotBlank;

/**
 * An IMetaAnalyzer implementation that supports GitHub via the api
 *
 * @author Jadyn Jaeger
 * @since 4.10.0
 */
public class GithubMetaAnalyzer extends AbstractMetaAnalyzer {

    private static final Logger LOGGER = Logger.getLogger(GithubMetaAnalyzer.class);

    private enum VersionType {
        RELEASE,
        COMMIT;
    }
    private static final VersionType DEFAULT_VERSION_TYPE = VersionType.RELEASE;
    private static final String REPOSITORY_DEFAULT_URL = "https://github.com";
    private String repositoryUrl;
    private String repositoryUser;
    private String repositoryPassword;

    GithubMetaAnalyzer() {
        this.repositoryUrl = REPOSITORY_DEFAULT_URL;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setRepositoryBaseUrl(String baseUrl) {
        this.repositoryUrl = baseUrl;
    }

    /**
     * {@inheritDoc}
     */
    public boolean isApplicable(final Component component) {
        return component.getPurl() != null && PackageURL.StandardTypes.GITHUB.equals(component.getPurl().getType());
    }

    /**
     * {@inheritDoc}
     */
    public RepositoryType supportedRepositoryType() {
        return RepositoryType.GITHUB;
    }

    /**
     * Checks whether the pURL version is a release or commit
     * @param component Component Object
     * @param repository The GH Repository Object defined by the pURL
     * @return VersionType
     * @throws IOException when GitHub API Calls fail
     */
    private VersionType get_version_type(final Component component, GHRepository repository) throws IOException {
        if (component.getPurl().getVersion() == null){
            LOGGER.debug(String.format("Version is not set, assuming %s", DEFAULT_VERSION_TYPE.name()));
            return DEFAULT_VERSION_TYPE;
        }
        if (repository.getReleaseByTagName(component.getPurl().getVersion()) != null){
            LOGGER.debug("Version is release");
            return VersionType.RELEASE;
        } else {
            LOGGER.debug("Version is commit");
            return VersionType.COMMIT;
        }
    }

    /**
     * {@inheritDoc}
     */
    public MetaModel analyze(final Component component) {
        final MetaModel meta = new MetaModel(component);
        if (component.getPurl() != null) {
            try {
                final GitHub github;
                if (isNotBlank(repositoryUser) && isNotBlank(repositoryPassword)) {
                    github = GitHub.connect(repositoryUser, repositoryPassword);
                } else if (isBlank(repositoryUser) && isNotBlank(repositoryPassword)) {
                    github = GitHub.connectUsingOAuth(repositoryUrl, repositoryPassword);
                } else {
                    github = GitHub.connectAnonymously();
                }

                GHRepository repository = github.getRepository(String.format("%s/%s", urlEncode(component.getPurl().getNamespace()), urlEncode(component.getPurl().getName())));
                LOGGER.debug(String.format("Repos is at %s", repository.getUrl()));

                final VersionType version_type = get_version_type(component, repository);

                if (version_type == VersionType.RELEASE) {
                    GHRelease latest_release = repository.getLatestRelease();
                    if (latest_release != null) {
                        meta.setLatestVersion(latest_release.getTagName());
                        LOGGER.debug(String.format("Latest version: %s", meta.getLatestVersion()));
                    }
                    GHRelease current_release = repository.getReleaseByTagName(component.getPurl().getVersion());
                    if (current_release != null) {
                        meta.setPublishedTimestamp(current_release.getPublished_at());
                        LOGGER.debug(String.format("Current version published at: %s", meta.getPublishedTimestamp()));
                    }
                }

                if (version_type == VersionType.COMMIT) {
                    GHBranch default_branch = repository.getBranch(repository.getDefaultBranch());
                    GHCommit latest_release = repository.getCommit(default_branch.getSHA1());
                    meta.setLatestVersion(latest_release.getSHA1());
                    LOGGER.debug(String.format("Latest version: %s", meta.getLatestVersion()));
                    GHCommit current_release = repository.getCommit(component.getPurl().getVersion());
                    meta.setPublishedTimestamp(current_release.getCommitDate());
                    LOGGER.debug(String.format("Current version published at: %s", meta.getPublishedTimestamp()));
                }
            } catch (IOException ex) {
                handleRequestException(LOGGER, ex);
            } catch (Exception ex) {
                throw new MetaAnalyzerException(ex);
            }
        }
        return meta;
    }
}
