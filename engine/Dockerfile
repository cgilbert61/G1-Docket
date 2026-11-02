FROM python:3.11-slim

WORKDIR /app

# Harden login definitions, permissions, and create unprivileged docket user
RUN sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs && \
    sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs && \
    sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/' /etc/login.defs && \
    sed -i 's/^UMASK.*/UMASK           027/' /etc/login.defs && \
    chmod 0644 /etc/passwd /etc/group && \
    chmod 0640 /etc/shadow && \
    groupadd -g 10001 docket && \
    useradd -u 10001 -g docket -m -s /bin/bash docket

RUN pip install --no-cache-dir \
    "cryptography>=41.0.0" \
    "jsonschema>=4.20.0" \
    "pydantic>=2.5.0" \
    "fastapi>=0.109.0" \
    "uvicorn>=0.27.0" \
    "sqlalchemy>=2.0.25" \
    "httpx>=0.26.0" \
    "pyjwt>=2.8.0" \
    "openpyxl>=3.1.2" \
    "psycopg2-binary>=2.9.9"

COPY pyproject.toml LICENSE ./
COPY schemas ./schemas
COPY registry ./registry
COPY engine ./engine
COPY snapshot ./snapshot
COPY examples ./examples
RUN pip install --no-cache-dir --no-deps -e .

RUN mkdir -p /var/lib/pod/public_keys /var/lib/pod/state && \
    chown -R docket:docket /app /var/lib/pod

VOLUME ["/var/lib/pod/public_keys", "/var/lib/pod/state"]
ENV POD_PUBLIC_KEY_DIR=/var/lib/pod/public_keys
EXPOSE 8083

USER docket:docket

CMD ["uvicorn", "engine.service:create_engine_app", "--factory", "--host", "0.0.0.0", "--port", "8083"]
