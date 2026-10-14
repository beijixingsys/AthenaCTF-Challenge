#!/bin/sh
cp -f ./onboarding_guard.py /app/onboarding_guard.py
cp -f ./onboarding_memory_store.py /app/onboarding_memory_store.py
cp -f ./packet_timeline.py /app/packet_timeline.py
rm -f /app/__pycache__/onboarding_guard.*.pyc
rm -f /app/__pycache__/onboarding_memory_store.*.pyc
rm -f /app/__pycache__/packet_timeline.*.pyc
