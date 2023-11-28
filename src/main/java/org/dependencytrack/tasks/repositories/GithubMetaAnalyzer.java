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
 * Copyright (c) Steve Springett. All Rights Reserved.
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
import java.util.regex.Pattern;

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

    private static final int VERSION_TYPE_RELEASE = 1;
    private static final int VERSION_TYPE_COMMIT = 2;
    private static final String VERSION_TYPE_PATTERN = "[a-f0-9]{6,40}";
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
    @Override
    public void setRepositoryUsernameAndPassword(String username, String password) {
        this.repositoryUser = username;
        this.repositoryPassword = password;
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

                Pattern version_pattern = Pattern.compile(VERSION_TYPE_PATTERN);
                final int version_type;
                if (version_pattern.matcher(component.getPurl().getVersion()).find()) {
                    LOGGER.debug("Version is commit");
                    version_type = VERSION_TYPE_COMMIT;
                } else {
                    LOGGER.debug("Version is release");
                    version_type = VERSION_TYPE_RELEASE;
                }

                GHRepository repository = github.getRepository(String.format("%s/%s", component.getPurl().getNamespace(), component.getPurl().getName()));
                LOGGER.debug(String.format("Repos is at %s", repository.getUrl()));
                if (version_type == VERSION_TYPE_RELEASE) {
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
                } else {
                    GHBranch default_branch = repository.getBranch(repository.getDefaultBranch());
                    GHCommit latest_release = repository.getCommit(default_branch.getSHA1());
                    GHCommit current_release = repository.getCommit(component.getPurl().getVersion());
                    meta.setLatestVersion(latest_release.getSHA1());
                    LOGGER.debug(String.format("Latest version: %s", meta.getLatestVersion()));
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
