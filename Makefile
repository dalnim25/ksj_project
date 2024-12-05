all:
	docker build -t test .
	docker run -it -d -p 5000:5000 --name test test

exec:
	docker exec -it test /bin/bash

clean:
	docker stop `docker ps -aq`;
	docker rm `docker ps -aq`;
	docker rmi `docker images -aq`;

re: clean
	$(Make) all

.PHONY: all clean re fclean exec