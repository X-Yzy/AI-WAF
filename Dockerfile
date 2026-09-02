ARG PYTHON_IMAGE=python:3.12-slim-bookworm
FROM ${PYTHON_IMAGE}

ARG PIP_INDEX_URL=https://mirrors.aliyun.com/pypi/simple/
ARG APT_MIRROR=https://mirrors.aliyun.com/debian
ARG APT_SECURITY_MIRROR=https://mirrors.aliyun.com/debian-security

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_INDEX_URL=${PIP_INDEX_URL} \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    WAD_MODEL_ROOT=/app/models/current \
    WAD_RUNTIME_ROOT=/app/runtime

# The root image contains the complete reproducible project. Its default
# process is the online API; host-side `python run.py ui` owns training and WAF
# orchestration because it has access to the host Docker engine.
RUN set -eux; \
    rm -f /etc/apt/sources.list /etc/apt/sources.list.d/*; \
    printf '%s\n' \
      'Types: deb' \
      "URIs: ${APT_MIRROR}" \
      'Suites: bookworm bookworm-updates' \
      'Components: main' \
      'Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg' \
      '' \
      'Types: deb' \
      "URIs: ${APT_SECURITY_MIRROR}" \
      'Suites: bookworm-security' \
      'Components: main' \
      'Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg' \
      > /etc/apt/sources.list.d/debian.sources; \
    printf '%s\n' \
      'Acquire::Retries "3";' \
      'Acquire::http::Timeout "20";' \
      'Acquire::https::Timeout "20";' \
      > /etc/apt/apt.conf.d/99-wad-cn-mirror; \
    groupadd -r appuser; \
    useradd -r -g appuser -u 10001 appuser; \
    apt-get update; \
    apt-get install -y --no-install-recommends libgomp1; \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN python -m pip install --no-cache-dir --no-compile --index-url "${PIP_INDEX_URL}" -r requirements.txt

# Include the actual organized dataset, training/evaluation code, tests,
# generator and documentation so every dashboard job works inside Docker.
COPY --chown=appuser:appuser . .

RUN mkdir -p /app/runtime && chown -R appuser:appuser /app/runtime
USER appuser

EXPOSE 8000 8080

CMD ["uvicorn", "src.runtime_api:app", "--host", "0.0.0.0", "--port", "8000"]
