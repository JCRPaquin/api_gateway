[![Coverage Status](https://coveralls.io/repos/github/adsabs/api_gateway/badge.svg?branch=fix-github-action)](https://coveralls.io/github/adsabs/api_gateway?branch=fix-github-action)
# api_gateway

SciX API Gateway, the core API module for SciX

## Getting Started

These instructions will get you a copy of the project up and running in a docker container or on your local machine for development purposes.

### Prerequisites

To run this project, you will need:

- Python 3.6 or higher
- Docker


### Configuration

Before running the project, you should update the configuration in `config.py`. This file contains settings that are necessary for the proper operation of the application, such as database connection information and secret keys. Make sure to replace the placeholders with the actual values.

#### Kafka request telemetry

Kafka request events are best-effort telemetry. The producer keeps `acks=0` and
uses `KAFKA_PRODUCER_SERVICE_MAX_BLOCK_MS = 0`, so metadata unavailability,
buffer pressure, serialization errors, and synchronous send failures cause the
event to be dropped immediately. They do not delay or alter the HTTP response.
The request path never waits for delivery or flushes the producer.

Kafka is not included in the Compose stack. If request telemetry is enabled,
the configured bootstrap brokers must be reachable from the gateway, but must
not be exposed to untrusted networks. Production brokers must require
authenticated clients, authorize this gateway only to write its request topic,
and use encrypted transport. The current producer configuration supplies only
bootstrap addresses; configure the corresponding Kafka authentication and TLS
settings before enabling it in such an environment. Broker or network
availability must not be treated as a requirement for serving API requests,
because telemetry is intentionally dropped whenever immediate admission is
not possible.

### Running the application

To start the application, navigate to the project directory in your terminal and run the following command:

```bash
 docker compose up
```

This command will start all the services defined in the docker-compose.yml file. The API should now be running at `http://localhost:5000`.




## Development

### Running the tests

To run the test and see coverage, navigate to the project directory in your terminal and run:

```bash
# setuptools>=58 breaks support for use_2to3 that is used by ConcurrentLogHandler in adsmutils
pip install setuptools==57.5.0 

# Install dependencies
pip install .[dev]

# Run the test and create coverage report
pytest
```


### Running the application

To install and run the application without Docker, navigate to the project directory in your terminal and run the following commands:

```bash
# setuptools>=58 breaks support for use_2to3 that is used by ConcurrentLogHandler in adsmutils
pip install setuptools==57.5.0 

# Install dependencies
pip install .

# Start the application 
python wsgi.py
```

### Database versioning

Database versioning is managed using Alembic. You can upgrade to the latest revision or downgrade to a previous one using the following commands:

```bash
# Upgrade to latest revision
alembic upgrade <revision>

# Downgrade revision
alembic downgrade <revision>

# Create a new revision
alembic revision --autogenerate -m "revision description"
```
