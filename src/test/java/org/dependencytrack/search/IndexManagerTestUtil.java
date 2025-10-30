package org.dependencytrack.search;

import org.apache.lucene.index.IndexWriter;
import org.junit.jupiter.api.Assertions;

import java.io.IOException;
import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

public class IndexManagerTestUtil {
    private IndexManagerTestUtil() { }

    public static void commitIndex(final IndexManager indexManager) {
        final IndexWriter indexWriter;
        try {
            indexWriter = indexManager.getIndexWriter();
        } catch (IOException e) {
            Assertions.fail("Unable to get IndexWriter", e);
            return;
        }
        try {
            indexWriter.forceMerge(1);
            indexWriter.commit();
            indexWriter.flush();
        } catch (IOException e) {
            Assertions.fail("Unable to flush IndexWriter", e);
            return;
        }
        await("Indexer flush")
                .atMost(Duration.ofSeconds(5))
                .untilAsserted(() -> assertThat(indexWriter.hasUncommittedChanges()).isFalse());
    }
}
