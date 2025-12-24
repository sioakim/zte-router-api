FROM python:3.12-alpine

WORKDIR /app

# Create non-root user
RUN adduser -D appuser

# Copy application files
COPY --chown=appuser:appuser index.html server.py ./

USER appuser

EXPOSE 8080

ENV PORT=8080
ENV ZTE_API_URL=http://zte-api-server:8000

CMD ["python3", "server.py"]
