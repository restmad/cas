package org.apereo.cas.git;

import lombok.Builder;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apache.commons.io.output.ByteArrayOutputStream;
import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.api.MergeCommand;
import org.eclipse.jgit.lib.Constants;
import org.eclipse.jgit.lib.ObjectId;
import org.eclipse.jgit.revwalk.RevWalk;
import org.eclipse.jgit.transport.ChainingCredentialsProvider;
import org.eclipse.jgit.transport.CredentialsProvider;
import org.eclipse.jgit.treewalk.TreeWalk;
import org.eclipse.jgit.treewalk.filter.TreeFilter;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * This is {@link GitRepository}.
 *
 * @author Misagh Moayyed
 * @since 6.1.0
 */
@Slf4j
@RequiredArgsConstructor
public class GitRepository {
    /**
     * The constant TIMEOUT_SECONDS.
     */
    private static final int TIMEOUT_SECONDS = 5;

    /**
     * The Git instance.
     */
    private final Git gitInstance;

    private final List<CredentialsProvider> credentialsProvider;

    /**
     * Gets repository directory.
     *
     * @return the repository directory
     */
    public File getRepositoryDirectory() {
        return this.gitInstance.getRepository().getDirectory().getParentFile();
    }

    /**
     * Gets repository file.
     *
     * @param gitObject the git object
     * @return the repository file
     */
    public File getRepositoryFile(final GitObject gitObject) {
        return new File(getRepositoryDirectory(), gitObject.getTreeWalk().getPathString());
    }

    /**
     * Gets objects in repository.
     *
     * @return the objects in repository
     */
    @SneakyThrows
    public Collection<GitObject> getObjectsInRepository() {
        return getObjectsInRepository(TreeFilter.ALL);
    }

    /**
     * Gets objects in repository.
     *
     * @param filter the filter
     * @return the objects in repository
     */
    @SneakyThrows
    public Collection<GitObject> getObjectsInRepository(final TreeFilter filter) {
        val repository = this.gitInstance.getRepository();
        val head = repository.resolve(Constants.HEAD);

        try (val walk = new RevWalk(repository)) {
            val commit = walk.parseCommit(head);
            val tree = commit.getTree();
            try (val treeWalk = new TreeWalk(repository)) {
                treeWalk.addTree(tree);
                treeWalk.setRecursive(true);
                treeWalk.setFilter(filter);
                val list = new ArrayList<GitObject>();
                while (treeWalk.next()) {
                    val object = readObject(treeWalk);
                    list.add(object);
                }
                return list;
            }
        }
    }

    /**
     * Read object.
     *
     * @param treeWalk the tree walk
     * @return the git object
     */
    @SneakyThrows
    public GitObject readObject(final TreeWalk treeWalk) {
        val objectId = treeWalk.getObjectId(0);
        val repository = this.gitInstance.getRepository();
        val loader = repository.open(objectId);
        val out = new ByteArrayOutputStream();
        loader.copyTo(out);
        return GitObject.builder()
            .content(out.toString(StandardCharsets.UTF_8))
            .treeWalk(treeWalk)
            .objectId(objectId)
            .build();
    }

    /**
     * Commit all.
     *
     * @param message the message
     */
    @SneakyThrows
    public void commitAll(final String message) {
        this.gitInstance.add().addFilepattern(".").call();
        this.gitInstance.commit()
            .setMessage(message)
            .setAll(true)
            .setAuthor("CAS", "cas@apereo.org")
            .call();
    }

    /**
     * Push.
     */
    @SneakyThrows
    public void push() {
        if (!this.credentialsProvider.isEmpty()) {
            val providers = this.credentialsProvider.toArray(CredentialsProvider[]::new);
            this.gitInstance.push()
                .setTimeout(TIMEOUT_SECONDS)
                .setPushAll()
                .setCredentialsProvider(new ChainingCredentialsProvider(providers))
                .call();
        } else {
            LOGGER.debug("No credentials are provided. Changes will not be pushed to repository");
        }
    }

    /**
     * Pull repository changes.
     *
     * @return the boolean
     */
    @SneakyThrows
    public boolean pull() {
        val remotes = this.gitInstance.getRepository().getRemoteNames();
        if (!remotes.isEmpty()) {
            return this.gitInstance.pull()
                .setTimeout(TIMEOUT_SECONDS)
                .setFastForward(MergeCommand.FastForwardMode.FF_ONLY)
                .setRebase(false)
                .setProgressMonitor(new LoggingGitProgressMonitor())
                .call()
                .isSuccessful();
        }
        return false;
    }

    /**
     * The type Git object.
     */
    @Builder
    @Getter
    public static class GitObject {
        private final String content;
        private final TreeWalk treeWalk;
        private final ObjectId objectId;
    }
}
