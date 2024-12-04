all:
	docker build -t test .
	docker run -it -d --name test test

exec:
	docker exec -it test /bin/bash

clean:
	docker stop test;
	docker rm test;
	docker rmi test;

fclean: clean
	docker stop `docker ps -aq`;
	docker rm `docker ps -aq`;
	docker rmi `docker images -aq`;

re: fclean
	$(Make) all

.PHONY: all clean re fclean exec