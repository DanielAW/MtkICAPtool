docker build -t ndk .
#docker-compose build ndk

docker run -v "$PWD":/usr/src/myapp -w /usr/src/myapp --rm ndk:latest make
#docker-compose run -v "$PWD":/usr/src/myapp -w /usr/src/myapp --rm ndk make
#don't use this:
#docker-compose run --rm ndk make

#running
docker run -it ndk
