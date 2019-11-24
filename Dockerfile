FROM openjdk

RUN mkdir -p /app 

ADD logstash-7.4.2.tar.gz /app

COPY lib/logstash/outputs/tcp.rb /app/logstash-7.4.2/vendor/bundle/jruby/2.5.0/gems/logstash-output-tcp-6.0.0/lib/logstash/outputs/tcp.rb

EXPOSE 4888

CMD ["/app/logstash-7.4.2/bin/logstash", "-f", "/tmp/logstash-sample.conf"]
