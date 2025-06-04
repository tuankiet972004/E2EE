FROM python:3.10-slim

RUN apt-get update && \
    apt-get install -y python3-tk && \
    apt-get install -y libx11-6 && \
    apt-get clean

WORKDIR /app

COPY . .

RUN pip install --no-cache-dir -r requirements.txt


CMD ["python", "test.py"]
