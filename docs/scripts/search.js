---
layout: null
---
(function () {
	function getQueryVariable(variable) {
		var query = window.location.search.substring(1),
			vars = query.split("&");

		for (var i = 0; i < vars.length; i++) {
			var pair = vars[i].split("=");

			if (pair[0] === variable) {
				return pair[1];
			}
		}
	}

	function getPreview(query, content, previewLength) {
		previewLength = previewLength || (content.length * 2);

		var parts = query.split(" "),
			match = content.toLowerCase().indexOf(query.toLowerCase()),
			matchLength = query.length,
			preview;

		// Find a relevant location in content
		for (var i = 0; i < parts.length; i++) {
			if (match >= 0) {
				break;
			}

			match = content.toLowerCase().indexOf(parts[i].toLowerCase());
			matchLength = parts[i].length;
		}

		// Create preview
		if (match >= 0) {
			var start = match - (previewLength / 2),
				end = start > 0 ? match + matchLength + (previewLength / 2) : previewLength;

			preview = content.substring(start, end).trim();

			if (start > 0) {
				preview = "..." + preview;
			}

			if (end < content.length) {
				preview = preview + "...";
			}

			// Return object with text and highlight info instead of HTML
			return {
				text: preview,
				highlights: parts
			};
		} else {
			// Use start of content if no match found
			preview = content.substring(0, previewLength).trim() + (content.length > previewLength ? "..." : "");
			return {
				text: preview,
				highlights: []
			};
		}
	}

	function highlightText(element, text, highlights) {
		element.textContent = ""; // Clear existing content
		
		if (highlights.length === 0) {
			element.textContent = text;
			return;
		}
		
		// Create regex pattern for highlighting, escaping special regex characters
		var escapedHighlights = highlights.map(function(h) {
			return h.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
		});
		var pattern = new RegExp("(" + escapedHighlights.join("|") + ")", "gi");
		var parts = text.split(pattern);
		
		parts.forEach(function(part) {
			if (part) {
				var isHighlight = highlights.some(function(h) {
					return h.toLowerCase() === part.toLowerCase();
				});
				
				if (isHighlight) {
					var strong = document.createElement("strong");
					strong.textContent = part;
					element.appendChild(strong);
				} else {
					element.appendChild(document.createTextNode(part));
				}
			}
		});
	}

	function displaySearchResults(results, query) {
		var searchResultsEl = document.getElementById("search-results"),
			searchProcessEl = document.getElementById("search-process");

		if (results.length) {
			// Clear existing content safely
			searchResultsEl.textContent = "";
			
			results.forEach(function (result) {
				var item = window.data[result.ref],
					contentPreview = getPreview(query, item.content, 170),
					titlePreview = getPreview(query, item.title);

				// Create DOM elements safely
				var li = document.createElement("li");
				var h4 = document.createElement("h4");
				var a = document.createElement("a");
				var p = document.createElement("p");
				var small = document.createElement("small");

				// Set safe attributes and content
				a.href = "{{ site.baseurl }}" + item.url.trim();
				
				// Safely highlight text without innerHTML
				highlightText(a, titlePreview.text, titlePreview.highlights);
				highlightText(small, contentPreview.text, contentPreview.highlights);
				
				// Build DOM structure
				h4.appendChild(a);
				p.appendChild(small);
				li.appendChild(h4);
				li.appendChild(p);
				searchResultsEl.appendChild(li);
			});

			searchProcessEl.innerText = "Showing";
		} else {
			searchResultsEl.style.display = "none";
			searchProcessEl.innerText = "No";
		}
	}

	window.index = lunr(function () {
		this.field("id");
		this.field("title", {boost: 10});
		this.field("category");
		this.field("url");
		this.field("content");
	});

	var query = decodeURIComponent((getQueryVariable("q") || "").replace(/\+/g, "%20")),
		searchQueryContainerEl = document.getElementById("search-query-container"),
		searchQueryEl = document.getElementById("search-query"),
		searchInputEl = document.getElementById("search-input");

	searchInputEl.value = query;
	searchQueryEl.innerText = query;
	searchQueryContainerEl.style.display = "inline";

	for (var key in window.data) {
		window.index.add(window.data[key]);
	}

	displaySearchResults(window.index.search(query), query); // Hand the results off to be displayed
})();