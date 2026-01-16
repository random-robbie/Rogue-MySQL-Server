FROM python:3.9-slim

WORKDIR /app

COPY RogueSQL_py3.py .

RUN mkdir -p /app/Downloads

EXPOSE 3306

ENTRYPOINT ["python", "RogueSQL_py3.py"]
