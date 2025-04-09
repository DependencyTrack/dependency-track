package org.dependencytrack.persistence;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class CollectionIntegerConverterTest {

    @Test
    void convertToDatastoreTest() {
        assertThat(new CollectionIntegerConverter().convertToDatastore(null)).isNull();
        assertThat(new CollectionIntegerConverter().convertToDatastore(List.of())).isEmpty();
        assertThat(new CollectionIntegerConverter().convertToDatastore(List.of(666))).isEqualTo("666");
        assertThat(new CollectionIntegerConverter().convertToDatastore(List.of(666, 123))).isEqualTo("666,123");
    }

    @Test
    void convertToAttributeTest() {
        assertThat(new CollectionIntegerConverter().convertToAttribute(null)).isNull();
        assertThat(new CollectionIntegerConverter().convertToAttribute("")).isNull();
        assertThat(new CollectionIntegerConverter().convertToAttribute(" ")).isNull();
        assertThat(new CollectionIntegerConverter().convertToAttribute("666")).containsOnly(666);
        assertThat(new CollectionIntegerConverter().convertToAttribute("666,123")).containsOnly(666, 123);
        assertThat(new CollectionIntegerConverter().convertToAttribute("666,, ,123")).containsOnly(666, 123);
    }

}