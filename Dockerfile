FROM python:3.11

RUN apt-get update && \
    apt-get install -y sudo \
    libpcap-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY . /app/

WORKDIR /app

RUN pip install -r requirements.txt
