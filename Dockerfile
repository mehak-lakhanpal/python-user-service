FROM python:3-alpine
LABEL maintainer="Mehak Lakhanpal"
COPY . /app
WORKDIR /app
RUN pip install -r requirements.txt
EXPOSE 8081
CMD [ "python", "app.py" ]
