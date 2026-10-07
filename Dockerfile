# AgentShield Console: one container runs the agents, the gateway and the web app.
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENV HOST=0.0.0.0 PORT=7860
EXPOSE 7860
CMD ["python", "-m", "agentshield.app"]
