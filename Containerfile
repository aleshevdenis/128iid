FROM ruby:3.2.0
USER root

# Update the base image.
RUN apt-get update -y && apt-get upgrade -y 

# Copy Files To Container.
ADD . "/opt/app/128iid/"

# Run Bundle Install
WORKDIR "/opt/app/128iid/"
RUN bundle install

# Set Entrypoint
ENTRYPOINT ["./scripts/entrypoint.sh"]
CMD ["help"]
