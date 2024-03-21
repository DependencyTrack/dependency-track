#!/usr/bin/env python3

# pip3 install --user defusedxml jinja2 requests
# python3 ./dev/scripts/cwe-dictionary-generate.py -v 4.13 \
#   -o src/main/java/org/dependencytrack/parser/common/resolver/CweDictionary.java

import os.path
import zipfile
from argparse import ArgumentParser
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryFile
from xml.etree import ElementTree

import jinja2
import requests
from defusedxml.ElementTree import parse as parse_etree

template = """/*
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
package {{ package }};

import javax.annotation.Generated;
import java.util.LinkedHashMap;
import java.util.Map;

@Generated(value = {{ script_name | tojson }}, date = {{ date | tojson }})
public final class CweDictionary {

    public static final Map<Integer, String> DICTIONARY = new LinkedHashMap<>();

    static {
        {% for id, name in definitions.items() -%}
        DICTIONARY.put({{ id }}, {{ name | tojson }});
        {% endfor %}
    }

    private CweDictionary() {
    }

}
"""

if __name__ == "__main__":
    arg_parser = ArgumentParser()
    arg_parser.add_argument("-p", "--package", default="org.dependencytrack.parser.common.resolver", help="Package name")
    arg_parser.add_argument("-o", "--output", type=Path, required=True, help="Output file path")
    arg_parser.add_argument("-v", "--version", type=str, required=True, help="CWE dictionary version")
    args = arg_parser.parse_args()

    with TemporaryFile(suffix=".zip") as tmp:
        with requests.get(f"https://cwe.mitre.org/data/xml/cwec_v{args.version}.xml.zip") as res:
            tmp.write(res.content)
        tmp.seek(0)
        with zipfile.ZipFile(tmp) as zip:
            with zip.open(f"cwec_v{args.version}.xml") as dict_file:
                tree: ElementTree = parse_etree(dict_file)

    tree_root = tree.getroot()
    namespaces = {"cwe": "http://cwe.mitre.org/cwe-7"}
    definitions: dict[int, str] = {}


    def process_definitions(xpath: str):
        for definition in tree_root.findall(xpath, namespaces=namespaces):
            definitions[int(definition.attrib["ID"])] = definition.attrib["Name"]


    process_definitions("./cwe:Categories/cwe:Category")
    process_definitions("./cwe:Weaknesses/cwe:Weakness")
    process_definitions("./cwe:Views/cwe:View")
    definitions = OrderedDict(sorted(definitions.items()))

    with args.output.open(mode="w") as out_file:
        out_file.write(jinja2.Environment().from_string(template).render(
            package=args.package,
            script_name=os.path.basename(__file__),
            date=datetime.now(timezone.utc).isoformat(),
            definitions=definitions
        ))
