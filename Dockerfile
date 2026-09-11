FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HOST=0.0.0.0 PORT=5000
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN python pipeline.py && useradd --create-home sentinaliq && chown -R sentinaliq:sentinaliq /app
USER sentinaliq
EXPOSE 5000
CMD ["python", "app.py"]
