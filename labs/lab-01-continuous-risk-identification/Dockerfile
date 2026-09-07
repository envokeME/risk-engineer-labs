FROM python:3.12-slim
WORKDIR /lab
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && useradd --create-home --uid 1000 learner
COPY --chown=learner:learner . .
RUN mkdir -p /lab/data /lab/runtime && chown -R learner:learner /lab/data /lab/runtime
USER learner
EXPOSE 8888
CMD ["python", "-m", "jupyterlab", "--ip=0.0.0.0", "--port=8888", "--no-browser"]
