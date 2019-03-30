FROM python:3

RUN apt-get update --fix-missing
RUN apt-get install -y iputils-ping
RUN apt-get install -y net-tools
RUN apt-get install -y curl

COPY webserver.py /webserver.py
RUN chmod +x /webserver.py
CMD /usr/bin/python webserver.py

