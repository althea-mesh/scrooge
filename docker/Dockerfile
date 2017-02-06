FROM debian
RUN apt-get update
RUN apt-get install -y wget automake gcc pkg-config make libev-dev python-dev bridge-utils ebtables
RUN wget -O - https://github.com/coreemu/core/archive/release-4.8.tar.gz | tar zxf -
WORKDIR core-release-4.8
RUN ./bootstrap.sh
RUN ./configure
RUN make 
RUN make install
COPY ./corescript.py corescript.py
CMD python ./corescript.py