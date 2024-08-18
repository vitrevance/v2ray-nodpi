# NoDPI - DPI Circumvention Mechanism Based on V2Ray

This project leverages the powerful capabilities of [V2Ray](https://www.v2ray.com/) to help users bypass Deep Packet Inspection (DPI) and enhance their online privacy and freedom.

## Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Installation Guide](#installation-guide)
- [Running the Project with Docker](#running-the-project-with-docker)
- [Configuration](#configuration)
- [References](#references)
- [License](#license)

## Introduction

DPI (Deep Packet Inspection) is a technology used by ISPs and network administrators to monitor and control internet traffic. This project aims to provide a simple mechanism to circumvent such restrictions using V2Ray, a versatile network tunneling tool.

## Features

- Bypass DPI restrictions
- Enhanced privacy and security
- Easy to configure and deploy
- Docker support for simplified setup

## Installation Guide

To get started with this project, you need to have Docker and Docker Compose installed on your machine.

### Running the Project with Docker

0. Clone this repository

1. Create a
`config.json`
file in the
`deploy/docker`
directory. You can use the provided
`example-config.json`
as a reference to fill in your V2Ray configuration.

2. Adjust the
`docker-compose.yaml`
file if necessary to suit your specific requirements.

3. Start the Docker container:
```bash
   docker-compose up -d
```


4. Your NoDPI server should now be running! You can check the logs to ensure everything is functioning correctly:
```bash
   docker-compose logs -f
```
5. Use V2Ray client to connect to the server.  
List of UI clients from the V2Ray website:
    - [Windows](https://www.v2ray.com/ru/ui_client/windows.html)
    - [Android](https://www.v2ray.com/ru/ui_client/android.html)
    - [iOS](https://www.v2ray.com/ru/ui_client/ios.html)


## Configuration

Make sure to configure your
config.json
file according to your needs. The V2Ray project provides extensive documentation on how to set up various configurations. You can refer to the V2Ray documentation for more details.

## References

For more information about V2Ray, please visit the official V2Ray GitHub repository: [V2Ray Project](https://www.v2ray.com/).