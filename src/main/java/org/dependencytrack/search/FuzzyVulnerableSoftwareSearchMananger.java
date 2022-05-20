package org.dependencytrack.search;

import alpine.common.logging.Logger;
import alpine.notification.Notification;
import alpine.notification.NotificationLevel;
import org.apache.commons.lang3.StringUtils;
import org.apache.lucene.document.Document;
import org.apache.lucene.index.CorruptIndexException;
import org.apache.lucene.index.IndexableField;
import org.apache.lucene.queryparser.classic.ParseException;
import org.apache.lucene.search.Query;
import org.apache.lucene.search.ScoreDoc;
import org.apache.lucene.search.TopDocs;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.notification.NotificationConstants;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.persistence.QueryManager;
import us.springett.parsers.cpe.CpeParser;
import us.springett.parsers.cpe.exceptions.CpeParsingException;
import us.springett.parsers.cpe.exceptions.CpeValidationException;
import us.springett.parsers.cpe.values.Part;

import java.io.IOException;
import java.util.*;

public class FuzzyVulnerableSoftwareSearchMananger {

    private static final Logger LOGGER = Logger.getLogger(FuzzyVulnerableSoftwareSearchMananger.class);

    private final boolean excludeComponentsWithPurl;

    public FuzzyVulnerableSoftwareSearchMananger(boolean excludeComponentsWithPurl) {
        this.excludeComponentsWithPurl = excludeComponentsWithPurl;
    }

    private class SearchTerm {
        private String product;
        private String vendor;

        public SearchTerm(String vendor,String product) {
            this.product = product;
            this.vendor = StringUtils.isBlank(vendor) ? "*" : vendor;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            SearchTerm that = (SearchTerm) o;
            return product.equals(that.product) && Objects.equals(vendor, that.vendor);
        }

        public String getVendor() {
            return vendor;
        }

        public String getProduct() {
            return product;
        }

        @Override
        public int hashCode() {
            return Objects.hash(product, vendor);
        }
    }

    public List<VulnerableSoftware> fuzzyAnalysis(QueryManager qm, final Component component, us.springett.parsers.cpe.Cpe parsedCpe) {
        List<VulnerableSoftware>  fuzzyList = Collections.emptyList();
        if (component.getPurl() == null || !excludeComponentsWithPurl) {
            HashSet<SearchTerm> searches = new HashSet<>();
            try {
                Part part = Part.ANY;
                String vendor = "*";
                if (parsedCpe != null) {
                    part = parsedCpe.getPart();
                    vendor = parsedCpe.getVendor();
                    searches.add(new SearchTerm(parsedCpe.getVendor(), parsedCpe.getProduct()));
                }
                if (component.getPurl() != null) {
                    searches.add(new SearchTerm(component.getPurl().getNamespace(), component.getPurl().getName()));
                }
                searches.add(new SearchTerm(component.getGroup(), component.getName()));
                for (SearchTerm search : searches) {
                    fuzzyList = fuzzySearch(qm, part, search.getVendor(), search.getProduct());
                    if (fuzzyList.isEmpty() && !"*".equals(search.getVendor())) {
                        fuzzyList = fuzzySearch(qm, part, "*", search.getProduct());
                    }
                    if (!fuzzyList.isEmpty()) {
                        break;
                    }
                }
                if (fuzzyList.isEmpty()) {
                    // If no luck, get fuzzier but not with small values as fuzzy 2 chars are easy to match
                    if (fuzzyList.isEmpty() && component.getName().length() > 2) {
                        us.springett.parsers.cpe.Cpe justThePart = new us.springett.parsers.cpe.Cpe(part, "*", "*", "*", "*", "*", "*", "*", "*", "*", "*");
                        // wildcard all components after part to constrain fuzzing to components of same type e.g. application, operating-system
                        String fuzzyTerm = getLuceneCpeRegexp(justThePart.toCpe23FS());
                        //The tilde makes it fuzzy. e.g. Will match libexpat1 to libexpat and product exact matches with vendor mismatch
                        fuzzyList = fuzzySearch(qm, "product:" + component.getName() + "~0.88 AND " + fuzzyTerm);
                    }
                }
            } catch (CpeValidationException cve) {
                LOGGER.error("Failed to validate fuzz search CPE", cve);
            }
        }
        return fuzzyList;
    }
    private List<VulnerableSoftware> fuzzySearch(QueryManager qm, Part part, String vendor, String product)  {
        try {
            us.springett.parsers.cpe.Cpe cpe = new us.springett.parsers.cpe.Cpe(part, vendor, product, "*", "*", "*", "*", "*", "*", "*", "*");
            String cpeSearch = getLuceneCpeRegexp(cpe.toCpe23FS());
            return fuzzySearch(qm, cpeSearch);
        } catch (CpeValidationException cpeValidationException) {
            LOGGER.error("Failed to validate fuzz search CPE", cpeValidationException);
            return Collections.emptyList();
        }
    }

    public SearchResult searchIndex(final String luceneQuery) {
        final SearchResult searchResult = new SearchResult();
        final List<Map<String, String>> resultSet = new ArrayList<>();
        IndexManager indexManager = VulnerableSoftwareIndexer.getInstance();
        try {
            final Query query = indexManager.getQueryParser().parse(luceneQuery);
            final TopDocs results = indexManager.getIndexSearcher().search(query,1000);

            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Searching for: " + luceneQuery + " - Total Hits: " + results.totalHits);
            }

            for (final ScoreDoc scoreDoc: results.scoreDocs) {
                final Document doc = indexManager.getIndexSearcher().doc(scoreDoc.doc);
                final Map<String, String> fields = new HashMap<>();
                for (final IndexableField field: doc.getFields()) {
                    if (StringUtils.isNotBlank(field.stringValue())) {
                        fields.put(field.name(), field.stringValue());
                    }
                }
                resultSet.add(fields);
            }
            searchResult.addResultSet(indexManager.getIndexType().name().toLowerCase(), resultSet);
        } catch (ParseException e) {
            LOGGER.error("Failed to parse search string", e);
            Notification.dispatch(new Notification()
                    .scope(NotificationScope.SYSTEM)
                    .group(NotificationGroup.INDEXING_SERVICE)
                    .title(NotificationConstants.Title.CORE_INDEXING_SERVICES)
                    .content("Failed to parse search string. Check log for details. " + e.getMessage())
                    .level(NotificationLevel.ERROR)
            );
        } catch (CorruptIndexException e) {
            LOGGER.error("Corrupted Lucene index detected", e);
            Notification.dispatch(new Notification()
                    .scope(NotificationScope.SYSTEM)
                    .group(NotificationGroup.INDEXING_SERVICE)
                    .title(NotificationConstants.Title.CORE_INDEXING_SERVICES)
                    .content("Corrupted Lucene index detected. Check log for details. " + e.getMessage())
                    .level(NotificationLevel.ERROR)
            );
        } catch (IOException e) {
            LOGGER.error("An I/O Exception occurred while searching Lucene index", e);
            Notification.dispatch(new Notification()
                    .scope(NotificationScope.SYSTEM)
                    .group(NotificationGroup.INDEXING_SERVICE)
                    .title(NotificationConstants.Title.CORE_INDEXING_SERVICES)
                    .content("An I/O Exception occurred while searching Lucene index. Check log for details. " + e.getMessage())
                    .level(NotificationLevel.ERROR)
            );
        }

        indexManager.close();
        return searchResult;
    }

    private List<VulnerableSoftware> fuzzySearch(QueryManager qm, String luceneQuery) {
        List<VulnerableSoftware>  fuzzyList = new LinkedList<>();
        SearchResult sr = searchIndex(luceneQuery);
        if (sr.getResults().containsKey("vulnerablesoftware")) {
            for (Map<String, String> result : sr.getResults().get("vulnerablesoftware")) {
                fuzzyList.add(qm.getObjectByUuid(VulnerableSoftware.class, result.get("uuid")));
            }
        }
        return fuzzyList;
    }

    public static String getLuceneCpeRegexp(String cpeString) {
        StringBuilder exp = new StringBuilder("cpe\\:");
        try {
            us.springett.parsers.cpe.Cpe cpe = CpeParser.parse(cpeString, true);
            if (cpeString.startsWith("cpe:2.3")) {
                exp.insert(0, "cpe23:/");
                exp.append("2\\.3\\:").append(cpe.getPart().getAbbreviation());
            } else {
                exp.insert(0, "cpe22:/");
                exp.append("\\/").append(cpe.getPart().getAbbreviation());
            }
            exp.append("\\:").append(getComponentRegex(cpe.getVendor()));
            exp.append("\\:").append(getComponentRegex(cpe.getProduct()));
            exp.append("\\:").append(getComponentRegex(cpe.getVersion()));
            exp.append("\\:").append(getComponentRegex(cpe.getUpdate()));
            exp.append("\\:").append(getComponentRegex(cpe.getEdition()));
            exp.append("\\:").append(getComponentRegex(cpe.getLanguage()));
            if (cpeString.startsWith("cpe:2.3")) {
                exp.append("\\:").append(getComponentRegex(cpe.getSwEdition()));
                exp.append("\\:").append(getComponentRegex(cpe.getTargetSw()));
                exp.append("\\:").append(getComponentRegex(cpe.getTargetHw()));
                exp.append("\\:").append(getComponentRegex(cpe.getOther()));
            }
            exp.append("/");
        } catch (CpeParsingException cpepe) {
            LOGGER.error("Unable to parse CPE to create RegularExpression", cpepe);
        }
        return exp.toString();
    }

    private static String getComponentRegex(String component) {
        if (component != null) {
            return component.replace("*", ".*");
        } else {
            return ".*";
        }
    }
}
