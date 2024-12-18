# Circle

Circle is a web-based file sharing application built with Go (server-side) and HTML/JS/CSS. It allows users to create private circles and invite guests to collaborate on file exchanges within those circles.

## Table of Contents

1. [Screenshots](#screenshots)
2. [Features](#features)
3. [Getting Started](#getting-started)
4. [Architecture](#architecture)
5. [License](#license)

## Screenshots

- **Login**:

![Login](./readme-assets/login.png)
![Guest](./readme-assets/guest.png)
![Register](./readme-assets/register.png)

- **Join as a guest**:

![Join](./readme-assets/join.png)

- **Circle**:

![Circles](./readme-assets/circles.png)
![Circle](./readme-assets/circle.png)

## Features

- User and Guest roles
  - Users can create circles and invite guests
  - Guests can only join one circle at a time
- Secure file sharing within circles
  - Users can upload, download, and exchange files with other members of their circle
- Flexible circle management
  - Users can add/remove guests from their circles
  - Circles can be kept private or made public

## Getting Started

1. Set up a `superkeys.txt` file in the project root with 64-character secret keys. This is used to create new user accounts.
2. Run the application using Docker Compose:

    ```sh
    docker-compose up --build
    ```

3. Access the web application at `http://localhost:8080`.

## Architecture

The Circle application is built using the following technologies:

- Server-side: Go
- Client-side: HTML, JavaScript, CSS
- Data storage: Postgres
- Containerization: Docker

## License

This project is licensed under the [MIT License](LICENSE).
