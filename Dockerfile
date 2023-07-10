FROM python:3.8
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# RUN apt-get update && apt-get install -y bluez dbus
# RUN /etc/init.d/dbus start
# RUN /usr/libexec/bluetooth/bluetoothd --debug &
COPY ./ .
EXPOSE 8000
CMD ["python", "scan.py"]