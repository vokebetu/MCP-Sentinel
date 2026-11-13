FROM postgres:17.11-alpine AS vector_build
RUN apk add --no-cache build-base git \
    && git clone --depth 1 --branch v0.8.7 https://github.com/pgvector/pgvector.git /tmp/pgvector \
    && cd /tmp/pgvector \
    && make OPTFLAGS="" with_llvm=no \
    && make with_llvm=no DESTDIR=/vector install

FROM postgres:17.11-alpine
COPY --from=vector_build /vector/ /
