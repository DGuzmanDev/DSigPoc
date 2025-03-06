#!/bin/bash

# Build the application
./mvnw clean package -DskipTests

# Run the application with PIN
java -jar target/firmador_poc-0.0.1-SNAPSHOT.jar "$1" "$2"
#java -jar target/firmador_poc-0.0.1-SNAPSHOT.jar "$1" "$2" --input input.pdf --output output.pdf --reason "Firma de prueba" --location "CR"
