#!/bin/bash

sudo python run.py --node R4 --cmd "pgrep -f [z]ebra | xargs kill -9"
sudo python run.py --node R4 --cmd "pgrep -f [b]gpd | xargs kill -9"
