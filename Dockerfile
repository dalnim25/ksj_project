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
    tar \
    net-tools \
    vim \
    lsof \
    procps \
    software-properties-common \
    && rm -rf /var/lib/apt/lists/*

# CodeQL CLI 설치
RUN wget https://github.com/github/codeql-cli-binaries/releases/latest/download/codeql-linux64.zip \
    && unzip codeql-linux64.zip -d /app \
    && rm codeql-linux64.zip

# Install Syft
RUN wget https://github.com/anchore/syft/releases/download/v0.70.0/syft_0.70.0_linux_amd64.tar.gz \
    && tar -xvzf syft_0.70.0_linux_amd64.tar.gz \
    && mv syft /usr/local/bin/ \
    && rm syft_0.70.0_linux_amd64.tar.gz

# Install Grype
RUN wget https://github.com/anchore/grype/releases/download/v0.77.0/grype_0.77.0_linux_amd64.tar.gz \
    && tar -xzf grype_0.77.0_linux_amd64.tar.gz \
    && mv grype /usr/local/bin/ \
    && rm grype_0.77.0_linux_amd64.tar.gz


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

RUN git clone https://github.com/github/codeql.git /app/codeql-repo

# 환경 변수 설정
ENV PATH="/app/codeql:${PATH}"
ENV FLASK_APP=guidelineDB.py
ENV FLASK_RUN_HOST=0.0.0.0
ENV FLASK_RUN_PORT=5000

# 애플리케이션 포트 노출
EXPOSE 5000

# 애플리케이션 실행
CMD ["flask", "run"]