#!/usr/bin/env bash

cd docs
bundle install
bundle exec jekyll build
cd ..