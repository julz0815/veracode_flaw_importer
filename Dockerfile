# Container image that runs your code
FROM veracode/api-signing
    
#RUN yum install httpie

# Copies your code file from your action repository to the filesystem path `/` of the container
COPY get_flaws.sh /get_flaws.sh
COPY jq-linux64 /jq-linux64

# Code file to execute when the docker container starts up (`get_flaws.sh`)
ENTRYPOINT ["bash","/get_flaws.sh"]
