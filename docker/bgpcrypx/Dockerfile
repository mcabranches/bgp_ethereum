FROM quaggabase:1
RUN apt-get install -y vim
RUN apt-get update --fix-missing
RUN apt-get install -y libtool
RUN apt-get install -y libssl-dev
RUN apt-get install -y python3-pip
RUN apt-get install -y pkg-config
RUN apt-get install -y libsecp256k1-dev
RUN pip3 install eth-testrpc
RUN pip3 install web3
RUN pip3 install ipython
RUN pip3 install netaddr
COPY ids.py /ids.py
COPY start.sh /start.sh
RUN chmod +x /start.sh
RUN apt-get install -y build-essential python-dev libnetfilter-queue-dev iptables
RUN DEBIAN_FRONTEND=noninteractive apt-get -y install tshark
RUN pip3 install NetfilterQueue
RUN pip3 install scapy
RUN pip3 install libbgp 
RUN pip3 install pyshark
WORKDIR /
