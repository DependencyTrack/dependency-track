# This file is part of Dependency-Track.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) OWASP Foundation. All Rights Reserved.

certs:
	mkdir -p ./certs
	openssl genrsa -out ./certs/ca-key.pem 4096
	openssl req -new -x509 -key ./certs/ca-key.pem -sha256 -subj '/CN=Kafka-CA/O=AcmeInc/C=DE' -days 3650 -out ./certs/ca-cert.pem
	openssl genrsa -out ./certs/broker-key.pem 4096
	openssl req -new -key ./certs/broker-key.pem -subj '/CN=Kafka-Broker/O=AcmeInc/C=DE' -out ./certs/broker.csr
	echo 'subjectAltName=DNS:localhost,DNS:kafka,IP:127.0.0.1' > ./certs/broker-cert-ext.cnf
	openssl x509 -req -in ./certs/broker.csr -CA certs/ca-cert.pem -CAkey ./certs/ca-key.pem -CAcreateserial -extfile ./certs/broker-cert-ext.cnf -days 365 -out ./certs/broker-cert.pem
	openssl genrsa -out ./certs/client-key.pem 4096
	openssl req -new -key ./certs/client-key.pem -subj '/CN=Kafka-Client/O=AcmeInc/C=DE' -out ./certs/client.csr
	openssl x509 -req -in ./certs/client.csr -CA certs/ca-cert.pem -CAkey ./certs/ca-key.pem -CAcreateserial -days 365 -out ./certs/client-cert.pem
	openssl pkcs12 -export -in ./certs/broker-cert.pem -inkey ./certs/broker-key.pem -name broker -out ./certs/broker-keystore.p12 -password pass:changeit
	keytool -import -trustcacerts -noprompt -alias ca -file ./certs/ca-cert.pem -keystore ./certs/truststore.p12 -storetype PKCS12 -storepass changeit
	echo 'changeit' > ./certs/broker-keystore-credentials
	echo 'changeit' > ./certs/truststore-credentials
.PHONY: certs