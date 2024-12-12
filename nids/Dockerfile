FROM python:3.11

RUN apt-get update && \
    apt-get install -y sudo \
    libpcap-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY nids.py /app/nids.py
COPY syn_scan.py /app/syn_scan.py
COPY .env /app/.env
COPY requirements.txt /app/requirements.txt

WORKDIR /app

RUN pip install -r requirements.txt
