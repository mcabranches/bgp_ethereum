FROM ubuntu:bionic

RUN apt-get update --fix-missing
RUN apt-get install -y quagga
RUN apt-get install -y iputils-ping
RUN apt-get install -y net-tools
RUN apt-get install -y curl
RUN echo "net.ipv4.conf.all.forwarding=1" | tee -a /etc/sysctl.conf 
RUN echo "net.ipv4.conf.default.forwarding=1" | tee -a /etc/sysctl.conf
RUN mkdir /run/quagga/
RUN chown -R quagga /run/quagga/
COPY bgpd.conf /etc/quagga/
COPY zebra.conf /etc/quagga/
COPY start.sh /
RUN chmod +x start.sh
CMD /start.sh
