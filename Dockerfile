FROM python:2
MAINTAINER twobot
ENV DEBIAN_FRONTEND noninteractive

RUN git clone https://github.com/curityio/nordicapis-python-openid-connect-client.git
RUN cd /nordicapis-python-openid-connect-client && pip install -r requirements.txt
