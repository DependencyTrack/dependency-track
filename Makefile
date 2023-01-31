start:
	$(shell cd postgres_ssl && sudo chmod +x ./generate-ssl.sh && ./generate-ssl.sh && cd ..)
	docker-compose up -d
.PHONY: start

stop:
	$(shell cd postgres_ssl && sudo chmod +x ./remove-ssl.sh && ./remove-ssl.sh && cd ..)
	docker-compose down -v
.PHONY: stop

restart:
	make stop
	make start
.PHONY: restart

