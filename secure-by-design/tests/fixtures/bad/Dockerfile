# Fixture con pattern volutamente insicuri: NON usare come esempio.
# sbd-expect-next: P-DOCKER-03
FROM node:latest AS build
RUN npm install
# sbd-expect-next: P-DOCKER-04
ADD https://example.com/tool.tar.gz /tmp/
# sbd-expect-next: P-SHELL-01
RUN curl -fsSL https://example.com/install.sh | sh
# sbd-expect-next: P-DOCKER-05
ENV DB_PASSWORD=supersecret123
# sbd-expect-next: P-SHELL-02
RUN chmod -R 777 /app
# sbd-expect-next: P-PKG-01
RUN pip install --extra-index-url https://pypi.example.com/simple internal-lib
# sbd-expect-next: P-TLS-02
RUN curl -k https://internal.example.com/cert.pem -o /tmp/cert.pem
# sbd-expect-next: P-WEB-03
ENV ASPNETCORE_ENVIRONMENT=Development
# sbd-expect-next: P-DOCKER-03,P-DOCKER-02
FROM debian:bookworm-slim
COPY --from=build /app /app
CMD ["/app/server"]
