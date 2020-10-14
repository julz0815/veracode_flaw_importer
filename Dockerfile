# Container image that runs your code
FROM openjdk:latest
    
#RUN yum install curl

# Copies your code file from your action repository to the filesystem path `/` of the container
COPY get_flaws.sh /get_flaws.sh

# Code file to execute when the docker container starts up (`get_flaws.sh`)
ENTRYPOINT ["/get_flaws.sh"]
