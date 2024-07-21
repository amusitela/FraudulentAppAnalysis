# Base image
FROM ubuntu:22.04

# Labels and Credits
LABEL \
    name="MobSF" \
    author="Ajin Abraham <ajin25@gmail.com>" \
    maintainer="Ajin Abraham <ajin25@gmail.com>" \
    contributor_1="OscarAkaElvis <oscar.alfonso.diaz@gmail.com>" \
    contributor_2="Vincent Nadal <vincent.nadal@orange.fr>" \
    description="Mobile Security Framework (MobSF) is an automated, all-in-one mobile application (Android/iOS/Windows) pen-testing, malware analysis and security assessment framework capable of performing static and dynamic analysis."

ENV DEBIAN_FRONTEND=noninteractive

# See https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#run
RUN apt update -y && apt install -y  --no-install-recommends \
    build-essential \
    locales \
    sqlite3 \
    fontconfig-config \
    libjpeg-turbo8 \
    libxrender1 \
    libfontconfig1 \
    libxext6 \
    fontconfig \
    xfonts-75dpi \
    xfonts-base \
    ttf-mscorefonts-installer \
    fonts-noto-cjk \
    python3 \
    python3-dev \
    python3-pip \
    wget \
    curl \
    git \
    jq \
    unzip \
    android-tools-adb && \
    locale-gen en_US.UTF-8 && \
    locale-gen zh_CN.UTF-8 && \
    apt upgrade -y

ENV MOBSF_USER=mobsf \
    MOBSF_PLATFORM=docker \
    MOBSF_ADB_BINARY=/usr/bin/adb \
    JDK_FILE=openjdk-20.0.2_linux-x64_bin.tar.gz \
    JDK_FILE_ARM=openjdk-20.0.2_linux-aarch64_bin.tar.gz \
    WKH_FILE=wkhtmltox_0.12.6.1-2.jammy_amd64.deb \
    WKH_FILE_ARM=wkhtmltox_0.12.6.1-2.jammy_arm64.deb \
    JAVA_HOME=/jdk-20.0.2 \
    PATH=$JAVA_HOME/bin:$PATH \
    LANG=zh_CN.UTF-8 \
    LANGUAGE=zh_CN.UTF-8 \
    LC_ALL=zh_CN.UTF-8 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONFAULTHANDLER=1 \
    POETRY_VERSION=1.6.1

# Install wkhtmltopdf & OpenJDK
ARG TARGETPLATFORM

# Copy the install script
COPY scripts/install_java_wkhtmltopdf.sh .

# Give execute permissions
RUN chmod +x install_java_wkhtmltopdf.sh

# Run the install script
RUN ./install_java_wkhtmltopdf.sh

RUN groupadd -g 9901 $MOBSF_USER
RUN adduser $MOBSF_USER --shell /bin/false -u 9901 --ingroup $MOBSF_USER --gecos "" --disabled-password

COPY poetry.lock pyproject.toml ./
RUN python3 -m pip install --upgrade --no-cache-dir pip poetry==${POETRY_VERSION} && \
    poetry config virtualenvs.create false && \
    poetry install --only main --no-root --no-interaction --no-ansi 

# Cleanup
RUN \
    apt remove -y \
        libssl-dev \
        libffi-dev \
        libxml2-dev \
        libxslt1-dev \
        python3-dev \
        wget && \
    apt clean && \
    apt autoclean && \
    apt autoremove -y && \
    rm -rf /var/lib/apt/lists/* /tmp/* > /dev/null 2>&1

WORKDIR /home/mobsf/Mobile-Security-Framework-MobSF
# Copy source code
COPY . .

# Check if Postgres support needs to be enabled.
# Disabled by default
ARG POSTGRES=False
ENV POSTGRES_USER=postgres \
    POSTGRES_PASSWORD=password \
    POSTGRES_DB=mobsf \
    POSTGRES_HOST=postgres

# Copy and set permissions for postgres_support.sh script
COPY scripts/postgres_support.sh .
RUN chmod +x scripts/postgres_support.sh

# Run postgres_support.sh script
RUN ./scripts/postgres_support.sh $POSTGRES

# Copy and set permissions for entrypoint script
COPY scripts/entrypoint.sh /home/mobsf/Mobile-Security-Framework-MobSF/scripts/entrypoint.sh
RUN chmod +x /home/mobsf/Mobile-Security-Framework-MobSF/scripts/entrypoint.sh

# Set ownership of the directory
RUN chown -R $MOBSF_USER:$MOBSF_USER /home/mobsf

# Switch to mobsf user
USER mobsf

# Run MobSF
ENTRYPOINT ["/home/mobsf/Mobile-Security-Framework-MobSF/scripts/entrypoint.sh"]
