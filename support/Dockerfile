FROM debian

RUN mkdir -p /pipeline/source
ADD build/bin/k8sniff /pipeline/source

CMD ["/pipeline/source/k8sniff"]
