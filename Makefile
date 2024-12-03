all:
	docker build -t test .
	docker run -d --name test test

clean:
	docker stop test;
	docker rm test;
	docker rmi test;

fclean: clean
	docker stop `docker ps -aq`;
	docker rm `docker ps -aq`;
	docker rmi `docker images -aq`;

re: clean
	$(Make) all

.PHONY: all clean re