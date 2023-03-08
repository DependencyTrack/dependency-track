package org.dependencytrack.util;

import org.junit.Assert;
import org.junit.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;

public class CacheStampedeBlockerTest {

    private ExecutorService service = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors() * 2);

    @Test
    public void highConcurrencyScenarioWithSuccessfulCallable() throws ExecutionException, InterruptedException {
        // Arrange
        CacheStampedeBlocker<String, Integer> cacheStampedeBlocker = new CacheStampedeBlocker<>("testCache", 10, true);
        Map<String, Integer> cache = new HashMap<>();
        for (int i = 0; i < 10; i++) {
            // Populating a "cache" with initial value
            cache.put("key-"+(i%10), 0);
        }
        List<Future<Optional<Integer>>> results = new ArrayList<>();

        // Act
        // 100 threads competing to update the cache for 10 distinct keys (10 threads / key). Only one should be able to increment the value.
        for (int i = 0; i < 10_000; i++) {
            final String key = "key-"+(i%10);
            results.add(service.submit(() -> cacheStampedeBlocker.readThroughOrPopulateCache(key, () -> {
                Thread.sleep(300);
                cache.put(key,cache.get(key).intValue()+1);
                return cache.get(key);
            })));
        }

        // Assert
        for (int i = 0; i < 10_000; i++) {
            Optional<Integer> result = results.get(i).get();
            Assert.assertTrue(result.isPresent());
            Assert.assertEquals("Iteration "+i+" failed", Integer.valueOf(1), result.get());
        }
    }

    @Test
    public void highConcurrencyScenarioWithErroneousCallable() throws ExecutionException, InterruptedException {
        // Arrange
        CacheStampedeBlocker<String, Integer> cacheStampedeBlocker = new CacheStampedeBlocker<>("testCache", 10, true);
        Map<String, Integer> cache = new HashMap<>();
        for (int i = 0; i < 10; i++) {
            cache.put("key-"+(i%10), 0);
        }
        List<Future<Optional<Integer>>> results = new ArrayList<>();

        // Act
        for (int i = 0; i < 100; i++) {
            final String key = "key-"+(i%10);
            results.add(service.submit(() -> cacheStampedeBlocker.readThroughOrPopulateCache(key, () -> {
                Thread.sleep(300);
                throw new RuntimeException("test");
            })));
        }

        // Assert
        for (int i = 0; i < 100; i++) {
            Optional<Integer> result = results.get(i).get();
            Assert.assertTrue(result.isEmpty());
        }
    }

    @Test
    public void retryScenarioWithNonRetryableException() {
        // Arrange
        CacheStampedeBlocker<String, Integer> cacheStampedeBlocker = new CacheStampedeBlocker<>("testCache", 10, true, 3);

        // Act
        AtomicInteger counter = new AtomicInteger();
        cacheStampedeBlocker.readThroughOrPopulateCache("key", () -> {
            counter.incrementAndGet();
            // Throwing ArithmeticException
            return 2 / 0;
        });

        // Assert
        Assert.assertEquals(1, counter.get());
    }

    @Test
    public void retryScenarioWithRetryableException() {
        // Arrange
        CacheStampedeBlocker<String, Integer> cacheStampedeBlocker = new CacheStampedeBlocker<>("testCache", 10, true, 3, Duration.ofMinutes(10).toMillis(), ArithmeticException.class);

        // Act
        AtomicInteger counter = new AtomicInteger();
        cacheStampedeBlocker.readThroughOrPopulateCache("key", () -> {
            counter.incrementAndGet();
            // Throwing ArithmeticException
            return 2 / 0;
        });

        // Assert
        Assert.assertEquals(3, counter.get());
    }
}
