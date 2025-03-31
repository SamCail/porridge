FROM ubuntu:22.04 

WORKDIR /code/

RUN apt update && apt upgrade -y && apt install -y build-essential python3-dev git python3-venv
RUN python3 --version

COPY . ./

RUN ./configure && ./test