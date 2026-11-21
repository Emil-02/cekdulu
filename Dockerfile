# Builds the API, the Telegram bot and the CLI into one small image.
#   docker build -t cekdulu .
#   docker run -p 8080:8080 --env-file .env cekdulu                      # API
#   docker run --env-file .env cekdulu cekdulu-telegram                  # bot Telegram
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/ ./cmd/...

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/ /usr/local/bin/
ENV CEKDULU_PORT=8080
EXPOSE 8080
CMD ["cekdulu-api"]
