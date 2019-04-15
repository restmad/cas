package org.apereo.cas.configuration.model.support.git;

import org.apereo.cas.configuration.support.RequiresModule;

import lombok.Getter;
import lombok.Setter;
import org.apache.commons.io.FileUtils;

import java.io.File;
import java.io.Serializable;

/**
 * This is {@link GitServiceRegistryProperties}.
 *
 * @author Misagh Moayyed
 * @since 6.1.0
 */
@RequiresModule(name = "cas-server-support-git-service-registry")
@Getter
@Setter
public class GitServiceRegistryProperties implements Serializable {
    private static final long serialVersionUID = 4194689836396653458L;

    /**
     * The address of the git repository.
     * Could be a URL or a file-system path.
     */
    private String repositoryUrl;

    /**
     * The branch to checkout and activate.
     */
    private String activeBranch = "master";

    /**
     * If the repository is to be cloned,
     * this will allow the list of branches to be fetched
     * separated by commas.
     */
    private String branchesToClone = "master";

    /**
     * Username used to access or push to the repository.
     */
    private String username;

    /**
     * Password used to access or push to the repository.
     */
    private String password;

    /**
     * Decide whether changes should be pushed back into the remote repository.
     */
    private boolean pushChanges;
    /**
     * Directory into which the repository would be cloned.
     */
    private File cloneDirectory = new File(FileUtils.getTempDirectory(), "cas-service-registry");
}
