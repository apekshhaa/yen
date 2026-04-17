FROM vxcontrol/kali-linux:latest

WORKDIR /app

# Install Python and essential tools
RUN apt-get update && apt-get install -y \
    python3 \
    python3-venv \
    python3-pip \
    git \
    curl \
    # Pentesting tools (already in Kali, but ensure they're installed)
    nmap \
    subfinder \
    nuclei \
    httpx-toolkit \
    metasploit-framework \
    sqlmap \
    nikto \
    dirb \
    gobuster \
    wfuzz \
    hydra \
    john \
    hashcat \
    aircrack-ng \
    wireshark-common \
    tcpdump \
    netcat-traditional \
    socat \
    && rm -rf /var/lib/apt/lists/*

# Install katana (web crawler for AI-driven analysis)
RUN go install github.com/projectdiscovery/katana/cmd/katana@latest 2>/dev/null || \
    (curl -sL https://github.com/projectdiscovery/katana/releases/latest/download/katana_linux_amd64.zip -o /tmp/katana.zip && \
     unzip /tmp/katana.zip -d /usr/local/bin/ && rm /tmp/katana.zip) || \
    echo "Katana installation failed - will use fallback crawling"

# Download and update nuclei templates during build
# Ensure templates are in /root/nuclei-templates for the scanning activities
RUN nuclei -update-templates -silent || true && \
    # Check where templates were installed and create symlink if needed
    if [ -d "/root/.local/nuclei-templates" ] && [ ! -d "/root/nuclei-templates" ]; then \
        ln -s /root/.local/nuclei-templates /root/nuclei-templates; \
    fi && \
    echo "Nuclei templates installed at:" && ls -la /root/nuclei-templates 2>/dev/null || ls -la /root/.local/nuclei-templates 2>/dev/null || echo "Templates location unknown"

# Create python symlink if needed
RUN ln -sf /usr/bin/python3 /usr/bin/python || true

# Upgrade pip
RUN python3 -m pip install --upgrade pip

# Copy project files
COPY pyproject.toml ./
COPY project ./project

# Install Python dependencies
RUN pip install --no-cache-dir -e .

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PATH="/usr/local/bin:${PATH}"

# Run the worker
CMD ["python", "-m", "project.run_worker"]
