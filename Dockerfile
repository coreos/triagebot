FROM registry.fedoraproject.org/fedora:34
RUN dnf install -y python3-pip && dnf clean all
COPY requirements.txt /
RUN pip install -r /requirements.txt
COPY triagebot.py /usr/local/bin
ENTRYPOINT ["/usr/local/bin/triagebot.py"]
