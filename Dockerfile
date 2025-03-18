FROM ubuntu:24.04

# Update default packages
RUN apt-get update

# Get Ubuntu packages
RUN apt-get install -y \
    build-essential \
    curl

# Update new packages
RUN apt-get update

RUN apt-get install -y python3 python3-pip python3.12-venv python3-poetry python3-maturin
RUN curl https://sh.rustup.rs -sSf | bash -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"
RUN cargo --help
# RUN apt-get install -y cargo 

WORKDIR /fastapi

ENV VIRTUAL_ENV=/opt/venv
RUN python3 -m venv $VIRTUAL_ENV
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

COPY app ./app
COPY src ./src
COPY README.md Cargo.toml pyproject.toml config.py main.py ./

RUN poetry install
# RUN cargo --version
RUN maturin dev

CMD [ "python", "main.py" ]
