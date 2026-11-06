# Lab image for the "victim" container: the agent plus the purple team harness.
# For real hosts use the systemd unit, as an agent in a container only sees that container.
FROM python:3.11-slim

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY server ./server
COPY agent ./agent
RUN pip install --no-cache-dir ".[agent-full]"

COPY config ./config
COPY purple ./purple

# Live purple mode refuses to run on a host without this marker.
RUN touch /etc/carylle-lab

CMD ["carylle-agent"]
