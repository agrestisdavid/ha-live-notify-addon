ARG BUILD_FROM
FROM ${BUILD_FROM}

# Install Python and pip
RUN apk add --no-cache python3 py3-pip py3-cryptography

WORKDIR /app

COPY requirements.txt .
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

COPY server.py .

# s6-overlay v3 service
COPY s6-overlay /etc/s6-overlay/
