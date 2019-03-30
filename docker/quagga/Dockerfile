FROM ubuntu:bionic

RUN apt-get update --fix-missing
RUN apt-get install -y quagga
RUN apt-get install -y iputils-ping
RUN apt-get install -y net-tools
RUN apt-get install -y curl
RUN sysctl -w net.ipv4.ip_forward=1
RUN mkdir /run/quagga/
RUN chown -R quagga /run/quagga/
COPY start.sh /
RUN chmod +x start.sh
CMD /start.sh

