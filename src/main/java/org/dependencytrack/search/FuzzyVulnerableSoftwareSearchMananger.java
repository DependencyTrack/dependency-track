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
    private final SearchManager sm = new SearchManager();

    public FuzzyVulnerableSoftwareSearchMananger(boolean excludeComponentsWithPurl) {
        this.excludeComponentsWithPurl = excludeComponentsWithPurl;
    }

    public List<VulnerableSoftware> fuzzyAnalysis(QueryManager qm, final Component component, us.springett.parsers.cpe.Cpe parsedCpe) {
        List<VulnerableSoftware>  fuzzyList = Collections.emptyList();
        if (component.getPurl() == null || !excludeComponentsWithPurl) {
            try {
                Part part = Part.ANY;
                String vendor = "*";
                if (parsedCpe != null) {
                    part = parsedCpe.getPart();
                    vendor = parsedCpe.getVendor();
                }
                us.springett.parsers.cpe.Cpe omitVersion = new us.springett.parsers.cpe.Cpe(part, vendor, component.getName(), "*", "*", "*","*", "*", "*", "*", "*");
                String cpeSearch = getCpeRegexp(omitVersion.toCpe23FS());
                fuzzyList = fuzzySearch(qm, component, cpeSearch);
                if (fuzzyList.isEmpty()) {
                    // Next search product without vendor
                    us.springett.parsers.cpe.Cpe justProduct = new us.springett.parsers.cpe.Cpe(part, "*", component.getName(), "*", "*", "*","*", "*", "*", "*", "*");
                    String justProductSearch = getCpeRegexp(justProduct.toCpe23FS());
                    if (!justProduct.equals(cpeSearch)) {
                        fuzzyList = fuzzySearch(qm, component, justProductSearch);
                    }
                    // If no luck, get fuzzier
                    if (fuzzyList.isEmpty()) {
                        us.springett.parsers.cpe.Cpe justThePart = new us.springett.parsers.cpe.Cpe(part, "*", "*", "*", "*", "*", "*", "*", "*", "*", "*");
                        // wildcard all components after part to constrain fuzzing to components of same type e.g. application, operating-system
                        String fuzzyTerm = getCpeRegexp(justThePart.toCpe23FS());
                        //The tilde makes it fuzzy. e.g. Will match libexpat1 to libexpat and product exact matches with vendor mismatch
                        fuzzyList = fuzzySearch(qm, component, "product:" + component.getName() + "~0.8 AND " + fuzzyTerm);
                    }
                }
            } catch (CpeValidationException cve) {
                LOGGER.error("Failed to validate fuzz search CPE", cve);
            }
        }
        return fuzzyList;
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

    private List<VulnerableSoftware> fuzzySearch(QueryManager qm, final Component component, String luceneQuery) {
        List<VulnerableSoftware>  fuzzyList = new LinkedList<>();
        //First Search product without vendor
        SearchResult sr = searchIndex(luceneQuery);
        if (sr.getResults().containsKey("vulnerablesoftware")) {
            for (Map<String, String> result : sr.getResults().get("vulnerablesoftware")) {
                fuzzyList.add(qm.getObjectByUuid(VulnerableSoftware.class, result.get("uuid")));
            }
        }
        return fuzzyList;
    }

    public static String getCpeRegexp(String cpeString) {
        StringBuilder exp = new StringBuilder("cpe\\:");
        try {
            us.springett.parsers.cpe.Cpe cpe = CpeParser.parse(cpeString, true);
            if (cpeString.startsWith("cpe:2.3")) {
                exp.insert(0, "cpe23:/");
                exp.append("2\\.3\\:").append(cpe.getPart().getAbbreviation());
            } else {
                exp.insert(0, "cpe22:/");
                exp.append("\\/" + cpe.getPart().getAbbreviation());
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
            while(exp.charAt(exp.length() -1 ) == '*' && exp.charAt(exp.length() -5 ) == '*') {
                exp.delete(exp.length() - 4, exp.length());
            }
            exp.append("/");
        } catch (CpeParsingException cpepe) {

        }
        return exp.toString();
    }

    private static String getComponentRegex(String component) {
        if (component != null) {
            return component.replaceAll("\\*", ".*");
        } else {
            return ".*";
        }
    }
}
