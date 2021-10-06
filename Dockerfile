# Copyright 2021 Hewlett Packard Enterprise Development LP
#
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included
# in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.
#
# (MIT License)

# This microservice is intended to be a dynamic ipxe building service. The
# purpose of this service is to respond to changes in the requested ipxe build
# environment and dynamically generate ipxe binaries used for booting.

# The most common form of this building environment is in support of https
# for downloading ipxe binaries from a secure location. The ipxe binaries
# themselves need to be dynamically recreated whenever the public CA cert
# changes.
FROM artifactory.algol60.net/csm-docker/stable/cray-tpsw-ipxe:@CRAY-TPSW-IPXE-VERSION@ as base
RUN mkdir /app
WORKDIR /app
COPY requirements.txt requirements_test.txt constraints.txt /app/

RUN apk --update upgrade --no-cache && \
    apk add \
      gcc \
      python3-dev \
      libc-dev \
      py3-pip openssl coreutils && \
    python3 -m pip install --upgrade pip && \
    python3 -m pip install --no-cache-dir -r /app/requirements.txt
RUN echo 'alias ll="ls -l"' > ~/.bashrc
RUN 'chown 65534:65534 -R /ipxe'
COPY /src/crayipxe /app/crayipxe
USER nobody:nobody
CMD ["/usr/bin/python3", "-m", "crayipxe.service"]
