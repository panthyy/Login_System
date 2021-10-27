FROM python:3.8

WORKDIR /app/

ADD requirements.txt /app/

RUN pip3 install --verbose -r requirements.txt

ADD . /app/

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]]
