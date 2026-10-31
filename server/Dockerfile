FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 LINTEL_DATA=/data TZ=Pacific/Auckland
RUN apt-get update && apt-get install -y --no-install-recommends tzdata && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# Face and person models from the OpenCV model zoo (Apache-2.0), pinned by hash.
RUN mkdir -p /app/models && cd /app/models \
 && python -c "import urllib.request as u; \
u.urlretrieve('https://media.githubusercontent.com/media/opencv/opencv_zoo/main/models/face_detection_yunet/face_detection_yunet_2023mar.onnx', 'face_detection_yunet_2023mar.onnx'); \
u.urlretrieve('https://media.githubusercontent.com/media/opencv/opencv_zoo/main/models/face_recognition_sface/face_recognition_sface_2021dec.onnx', 'face_recognition_sface_2021dec.onnx'); \
u.urlretrieve('https://media.githubusercontent.com/media/opencv/opencv_zoo/main/models/object_detection_yolox/object_detection_yolox_2022nov.onnx', 'object_detection_yolox_2022nov.onnx')" \
 && echo "8f2383e4dd3cfbb4553ea8718107fc0423210dc964f9f4280604804ed2552fa4  face_detection_yunet_2023mar.onnx" | sha256sum -c - \
 && echo "0ba9fbfa01b5270c96627c4ef784da859931e02f04419c829e83484087c34e79  face_recognition_sface_2021dec.onnx" | sha256sum -c - \
 && echo "c5c2d13e59ae883e6af3b45daea64af4833a4951c92d116ec270d9ddbe998063  object_detection_yolox_2022nov.onnx" | sha256sum -c -
# Face anti-spoofing models (Minivision, Apache-2.0), converted to ONNX in this repo; see antispoof/README.md.
COPY antispoof/*.onnx /app/models/
RUN cd /app/models \
 && echo "1cb86b65b7e204950a10a868049e1012c0892f6f908dc93587f29cf3b3794419  antispoof_2.7_80x80_minifasnetv2.onnx" | sha256sum -c - \
 && echo "0a4539e34fd8428967614df33657edbc8ffc0404049104a22dc7eb1589f378a9  antispoof_4.0_80x80_minifasnetv1se.onnx" | sha256sum -c -
ENV LINTEL_MODELS=/app/models
COPY lintel_server ./lintel_server
RUN useradd -r -u 1000 lintel && mkdir -p /data && chown lintel /data
USER lintel
VOLUME /data
EXPOSE 8443/tcp 47800/udp
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request,sys; urllib.request.urlopen(\"https://127.0.0.1:8443/\", context=__import__('ssl')._create_unverified_context())" || exit 1
CMD ["python", "-m", "lintel_server", "serve"]
