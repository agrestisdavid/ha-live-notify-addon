ARG BUILD_FROM
FROM ${BUILD_FROM}

# Install Python and pip
RUN apk add --no-cache python3 py3-pip py3-cryptography

# Working directory
WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

# Copy application
COPY server.py .
COPY run.sh /

# Make run script executable
RUN chmod a+x /run.sh

CMD [ "/run.sh" ]
