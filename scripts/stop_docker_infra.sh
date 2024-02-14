#!/bin/sh

echo "Stopping BE-1 ..."
docker stop be-1 || true

echo "Stopping BE-2 ..."
docker stop be-2 || true

echo "Stopping CL-1 ..."
docker stop cl-1 || true

echo "Stopping CL-2 ..."
docker stop cl-2 || true

echo "Done!"
