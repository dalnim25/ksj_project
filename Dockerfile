ARG PYTHON_VERSION=3.9
FROM python:${PYTHON_VERSION}-slim

# Python 공식 런타임 이미지를 기본 이미지로 사용
FROM python:3.9-slim

# 컨테이너 내부 작업 디렉토리 설정
WORKDIR /app

# 시스템 종속성 설치
RUN apt-get update && apt-get install -y \
    git \
    wget \
    curl \
    unzip \
    software-properties-common \
    && rm -rf /var/lib/apt/lists/*

# CodeQL CLI 설치
RUN wget https://github.com/github/codeql-cli-binaries/releases/latest/download/codeql-linux64.zip \
    && unzip codeql-linux64.zip -d /app \
    && rm codeql-linux64.zip

# Python 개발 및 보안 분석에 필요한 도구 설치
RUN pip install --no-cache-dir \
    flask \
    flask-cors \
    requests \
    pygments \
    spdx-tools \
    bandit

# 프로젝트 파일 복사, 현재 test경로
COPY . /app/

# 필요한 디렉토리 생성
RUN mkdir -p /app/results /app/sbom /app/codeql-repo

# 환경 변수 설정
ENV FLASK_APP=guidelineDB.py
ENV FLASK_RUN_HOST=0.0.0.0

# 애플리케이션 포트 노출
EXPOSE 5000

# 애플리케이션 실행
CMD ["flask", "run"]