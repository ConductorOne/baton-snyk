FROM gcr.io/distroless/static-debian11:nonroot
ENTRYPOINT ["/baton-snyk"]
COPY baton-snyk /