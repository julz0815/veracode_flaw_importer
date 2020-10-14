# Container image that runs your code
FROM ctcampbellcom/veracode-tools
    
#RUN yum install httpie

# Copies your code file from your action repository to the filesystem path `/` of the container
COPY get_flaws.sh /get_flaws.sh
COPY jq-linux64 /jq-linux64

env VERACODE_API_KEY_ID: '${{ secrets.VERACODE_API_ID }}'
env VERACODE_API_KEY_SECRET: '${{ secrets.VERACODE_API_KEY }}'

# Code file to execute when the docker container starts up (`get_flaws.sh`)
ENTRYPOINT ["bash","/get_flaws.sh"]
