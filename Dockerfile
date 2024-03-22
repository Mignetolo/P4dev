FROM ubuntu:20.04

RUN apt-get update && TZ=Europe/Warsaw && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    git \
    python3 \
    python3-pip \
    sudo \
    wget \
    curl \
    gnupg2 \
    lsb-release && rm -rf /var/lib/apt/lists/*

ENV TZ=Europe/Warsaw

RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone
RUN git clone https://github.com/jafingerhut/p4-guide.git
RUN /bin/bash -c "./p4-guide/bin/install-p4dev-v5.sh"

CMD ["/bin/bash"]
